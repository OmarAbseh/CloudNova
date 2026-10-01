"""Org-scoped operations: the domain layer over the Floatly Platform schema.

Every function here takes the signed-in user's access token and nothing else
that grants authority. None of them filter by ``org_id`` in application code
for security purposes — RLS already does that, and duplicating the rule in
Python would create two places for it to drift. Where an ``org_id`` does appear
in a query it is there to narrow a result set the database has *already*
restricted to orgs the caller belongs to.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cloudnova.platform.client import SupabaseClient, SupabaseError

# A scan can produce a lot of findings; insert them in batches so one request
# does not grow unbounded.
_FINDING_BATCH = 200


@dataclass(frozen=True)
class Org:
    id: str
    name: str
    role: str


def ensure_profile(client: SupabaseClient, token: str, user_id: str, email: str) -> None:
    """Make sure the user has a profile row.

    The schema deliberately has no ``auth.users`` trigger (that needs owner
    rights on the auth schema), so the first authenticated request does it.
    Best effort: a missing profile costs a display name, not access.
    """
    try:
        existing = client.select("profiles", token, params={"id": f"eq.{user_id}", "select": "id"})
        if not existing:
            client.insert("profiles", token, [{"id": user_id, "email": email}], returning=False)
    except SupabaseError:
        return


def list_orgs(client: SupabaseClient, token: str) -> list[Org]:
    """Every org the user belongs to, with their role in each.

    Read through ``memberships`` rather than ``organizations`` because the
    membership row is what carries the role. RLS on both tables means this can
    only ever return the caller's own orgs.
    """
    rows = client.select(
        "memberships",
        token,
        params={"select": "role,organizations(id,name)", "order": "created_at.asc"},
    )
    orgs: list[Org] = []
    for row in rows:
        org = row.get("organizations")
        if isinstance(org, dict) and org.get("id"):
            orgs.append(
                Org(
                    id=str(org["id"]),
                    name=str(org.get("name") or "Untitled"),
                    role=str(row.get("role") or "member"),
                )
            )
    return orgs


def create_org(client: SupabaseClient, token: str, user_id: str, name: str) -> Org:
    """Create an org. The schema's trigger makes the creator its owner."""
    rows = client.insert("organizations", token, [{"name": name, "created_by": user_id}])
    if not rows:
        raise SupabaseError("Could not create the organization.")
    row = rows[0]
    return Org(id=str(row["id"]), name=str(row.get("name") or name), role="owner")


def ensure_org(client: SupabaseClient, token: str, user_id: str, email: str) -> list[Org]:
    """Orgs for this user, creating a personal one if they have none.

    Without this a fresh signup lands on an empty dashboard with no way
    forward, since RLS hides every org they are not yet a member of.
    """
    orgs = list_orgs(client, token)
    if orgs:
        return orgs
    local = email.partition("@")[0] or "My"
    return [create_org(client, token, user_id, f"{local}'s workspace")]


def _target_row(org_id: str, path: str, user_id: str) -> dict[str, Any]:
    return {
        "org_id": org_id,
        "name": path,
        "kind": "iac",
        "identifier": path,
        "created_by": user_id,
    }


def find_or_create_target(
    client: SupabaseClient, token: str, org_id: str, path: str, user_id: str
) -> str:
    """Reuse the org's target for this path, or create it. Returns its id."""
    existing = client.select(
        "targets",
        token,
        params={"select": "id", "org_id": f"eq.{org_id}", "identifier": f"eq.{path}", "limit": "1"},
    )
    if existing:
        return str(existing[0]["id"])
    created = client.insert("targets", token, [_target_row(org_id, path, user_id)])
    if not created:
        raise SupabaseError("Could not create a target for that path.")
    return str(created[0]["id"])


def _finding_rows(
    org_id: str, scan_id: str, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for f in findings:
        raw_location = f.get("location")
        location: dict[str, Any] = raw_location if isinstance(raw_location, dict) else {}
        rows.append(
            {
                "org_id": org_id,
                "scan_id": scan_id,
                "check_id": f.get("check_id") or "UNKNOWN",
                "title": f.get("title") or "",
                "severity": f.get("severity") or "info",
                "confidence": f.get("confidence") or "high",
                "location_path": location.get("path") or "",
                "location_line": location.get("line"),
                "location_resource": location.get("resource"),
                "description": f.get("description") or "",
                "remediation": f.get("remediation") or "",
                "evidence": f.get("evidence"),
                # `references` is a reserved word in SQL; the column is renamed.
                "reference_urls": f.get("references") or [],
                "cis_controls": f.get("cis_controls") or [],
                "mitre_attack": f.get("mitre_attack") or [],
            }
        )
    return rows


def record_scan(
    client: SupabaseClient,
    token: str,
    *,
    org_id: str,
    user_id: str,
    path: str,
    result: dict[str, Any],
) -> str:
    """Persist a completed scan and its findings. Returns the scan id."""
    raw_summary = result.get("summary")
    summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
    target_id = find_or_create_target(client, token, org_id, path, user_id)

    scan_rows = client.insert(
        "scans",
        token,
        [
            {
                "org_id": org_id,
                "target_id": target_id,
                "status": "succeeded",
                "finished_at": "now()",
                "files_scanned": summary.get("files_scanned") or 0,
                "checks_run": summary.get("checks_run") or 0,
                "findings_count": summary.get("findings") or 0,
                "posture_score": summary.get("posture_score"),
                "grade": summary.get("grade"),
                "score_breakdown": summary.get("score_breakdown") or {},
                "errors": result.get("errors") or [],
                "created_by": user_id,
            }
        ],
    )
    if not scan_rows:
        raise SupabaseError("Could not save the scan.")
    scan_id = str(scan_rows[0]["id"])

    findings = result.get("findings")
    if isinstance(findings, list) and findings:
        rows = _finding_rows(org_id, scan_id, findings)
        for start in range(0, len(rows), _FINDING_BATCH):
            client.insert("findings", token, rows[start : start + _FINDING_BATCH], returning=False)
    return scan_id


def list_scans(
    client: SupabaseClient, token: str, org_id: str, *, limit: int = 25
) -> list[dict[str, Any]]:
    """Recent scans for an org, newest first."""
    return client.select(
        "scans",
        token,
        params={
            "select": "id,started_at,status,findings_count,posture_score,grade,targets(name,kind)",
            "org_id": f"eq.{org_id}",
            "order": "started_at.desc",
            "limit": str(limit),
        },
    )


def list_findings(client: SupabaseClient, token: str, scan_id: str) -> list[dict[str, Any]]:
    """Findings for one scan. RLS rejects a scan id from another org."""
    return client.select(
        "findings",
        token,
        params={"select": "*", "scan_id": f"eq.{scan_id}", "order": "severity.asc,check_id.asc"},
    )
