"""Org-scoped operations: what gets sent, and how RLS denials surface."""

from __future__ import annotations

import pytest

pytest.importorskip("httpx")
import httpx

from cloudnova.platform.client import SupabaseError
from cloudnova.platform.tenancy import (
    ensure_org,
    ensure_profile,
    find_or_create_target,
    list_findings,
    list_orgs,
    list_scans,
    record_scan,
)

SCAN_RESULT = {
    "summary": {
        "files_scanned": 3,
        "checks_run": 30,
        "findings": 2,
        "posture_score": 60,
        "grade": "D",
        "score_breakdown": {"critical": 40, "high": 20},
    },
    "findings": [
        {
            "check_id": "IAC_S3_PUBLIC_ACL",
            "title": "Public bucket",
            "severity": "critical",
            "confidence": "high",
            "location": {"path": "main.tf", "line": 4, "resource": "aws_s3_bucket.b"},
            "description": "d",
            "remediation": "r",
            "evidence": "acl = public-read",
            "references": ["https://example.test"],
            "cis_controls": ["1.1"],
            "mitre_attack": ["T1530"],
        },
        {
            "check_id": "IAC_SG_OPEN",
            "title": "Open SG",
            "severity": "high",
            "confidence": "medium",
            "location": {"path": "sg.tf"},
            "description": "d",
            "remediation": "r",
        },
    ],
    "errors": ["could not parse weird.tf"],
}


def _json(payload, status=200):
    return httpx.Response(status, json=payload)


# -- orgs ------------------------------------------------------------------


def test_list_orgs_reads_through_memberships_to_get_the_role(make_client):
    client, rec = make_client(
        [_json([{"role": "owner", "organizations": {"id": "org-1", "name": "Acme"}}])]
    )
    orgs = list_orgs(client, "user-jwt")
    assert [(o.id, o.name, o.role) for o in orgs] == [("org-1", "Acme", "owner")]
    # The role lives on the membership row, so that is what we select from.
    assert rec.path() == "/rest/v1/memberships"
    assert rec.bearer() == "user-jwt"


def test_list_orgs_skips_rows_with_no_embedded_org(make_client):
    client, _ = make_client([_json([{"role": "owner", "organizations": None}])])
    assert list_orgs(client, "user-jwt") == []


def test_ensure_org_returns_existing_without_creating(make_client):
    client, rec = make_client(
        [_json([{"role": "member", "organizations": {"id": "org-1", "name": "Acme"}}])]
    )
    orgs = ensure_org(client, "user-jwt", "user-1", "omar@example.test")
    assert len(orgs) == 1
    assert len(rec.requests) == 1  # no POST


def test_ensure_org_creates_a_personal_workspace_when_none(make_client):
    # Without this a fresh signup lands on a dashboard with no org and no way
    # to make one, because RLS hides every org they are not a member of.
    client, rec = make_client([_json([]), _json([{"id": "org-new", "name": "omar's workspace"}])])
    orgs = ensure_org(client, "user-jwt", "user-1", "omar@example.test")
    assert [o.name for o in orgs] == ["omar's workspace"]
    assert orgs[0].role == "owner"  # the schema trigger makes the creator owner
    assert rec.path() == "/rest/v1/organizations"
    assert rec.body()[0]["created_by"] == "user-1"


def test_create_org_failing_raises(make_client):
    client, _ = make_client([_json([]), _json([])])
    with pytest.raises(SupabaseError, match="Could not create"):
        ensure_org(client, "user-jwt", "user-1", "omar@example.test")


# -- profile ---------------------------------------------------------------


def test_ensure_profile_inserts_only_when_missing(make_client):
    client, rec = make_client([_json([]), _json([{"id": "user-1"}])])
    ensure_profile(client, "user-jwt", "user-1", "omar@example.test")
    assert len(rec.requests) == 2
    assert rec.body()[0] == {"id": "user-1", "email": "omar@example.test"}


def test_ensure_profile_is_a_noop_when_present(make_client):
    client, rec = make_client([_json([{"id": "user-1"}])])
    ensure_profile(client, "user-jwt", "user-1", "omar@example.test")
    assert len(rec.requests) == 1


def test_ensure_profile_swallows_errors(make_client):
    # A missing profile costs a display name, not access - never block login.
    client, _ = make_client([_json({"message": "boom"}, status=500)])
    ensure_profile(client, "user-jwt", "user-1", "omar@example.test")


# -- targets / scans / findings -------------------------------------------


def test_find_or_create_target_reuses_an_existing_row(make_client):
    client, rec = make_client([_json([{"id": "t-1"}])])
    assert find_or_create_target(client, "user-jwt", "org-1", "./infra", "user-1") == "t-1"
    assert len(rec.requests) == 1
    assert rec.last.url.params["identifier"] == "eq../infra"
    assert rec.last.url.params["org_id"] == "eq.org-1"


def test_find_or_create_target_creates_when_absent(make_client):
    client, rec = make_client([_json([]), _json([{"id": "t-2"}])])
    assert find_or_create_target(client, "user-jwt", "org-1", "./infra", "user-1") == "t-2"
    assert rec.body()[0]["org_id"] == "org-1"
    assert rec.body()[0]["kind"] == "iac"


def test_record_scan_writes_target_scan_and_findings(make_client):
    client, rec = make_client(
        [
            _json([{"id": "t-1"}]),  # target lookup
            _json([{"id": "scan-1"}]),  # scan insert
            httpx.Response(201, content=b""),  # findings insert (minimal)
        ]
    )
    scan_id = record_scan(
        client,
        "user-jwt",
        org_id="org-1",
        user_id="user-1",
        path="./infra",
        result=SCAN_RESULT,
    )
    assert scan_id == "scan-1"

    scan_row = rec.body(1)[0]
    assert scan_row["org_id"] == "org-1"
    assert scan_row["target_id"] == "t-1"
    assert scan_row["findings_count"] == 2
    assert scan_row["posture_score"] == 60
    assert scan_row["grade"] == "D"
    # The top-level error list is stored, not the summary's integer count.
    assert scan_row["errors"] == ["could not parse weird.tf"]

    findings = rec.body(2)
    assert len(findings) == 2
    first = findings[0]
    assert first["org_id"] == "org-1"
    assert first["scan_id"] == "scan-1"
    assert first["location_path"] == "main.tf"
    assert first["location_line"] == 4
    assert first["location_resource"] == "aws_s3_bucket.b"
    # `references` is a reserved SQL word, so the column is reference_urls.
    assert first["reference_urls"] == ["https://example.test"]
    assert "references" not in first


def test_record_scan_defaults_missing_finding_fields(make_client):
    client, rec = make_client(
        [_json([{"id": "t-1"}]), _json([{"id": "scan-1"}]), httpx.Response(201, content=b"")]
    )
    record_scan(
        client, "user-jwt", org_id="org-1", user_id="user-1", path="./x", result=SCAN_RESULT
    )
    second = rec.body(2)[1]
    assert second["location_line"] is None
    assert second["location_resource"] is None
    assert second["reference_urls"] == []
    assert second["cis_controls"] == []


def test_record_scan_with_no_findings_skips_the_findings_write(make_client):
    client, rec = make_client([_json([{"id": "t-1"}]), _json([{"id": "scan-1"}])])
    result = {"summary": {"findings": 0, "grade": "A", "posture_score": 0}, "findings": []}
    assert (
        record_scan(client, "user-jwt", org_id="org-1", user_id="user-1", path="./x", result=result)
        == "scan-1"
    )
    assert len(rec.requests) == 2


def test_record_scan_batches_large_finding_sets(make_client):
    many = {
        "summary": {"findings": 250},
        "findings": [
            {
                "check_id": f"C{i}",
                "title": "t",
                "severity": "low",
                "location": {"path": "p"},
                "description": "d",
                "remediation": "r",
            }
            for i in range(250)
        ],
    }
    client, rec = make_client(
        [
            _json([{"id": "t-1"}]),
            _json([{"id": "scan-1"}]),
            httpx.Response(201, content=b""),
            httpx.Response(201, content=b""),
        ]
    )
    record_scan(client, "user-jwt", org_id="org-1", user_id="user-1", path="./x", result=many)
    assert len(rec.requests) == 4  # target + scan + two finding batches
    assert len(rec.body(2)) == 200
    assert len(rec.body(3)) == 50


def test_record_scan_surfaces_an_rls_denial(make_client):
    # Writing into an org you do not belong to is refused by the database.
    client, _ = make_client(
        [
            _json([]),
            _json({"message": "new row violates row-level security policy"}, status=403),
        ]
    )
    with pytest.raises(SupabaseError, match="row-level security"):
        record_scan(
            client,
            "user-jwt",
            org_id="not-mine",
            user_id="user-1",
            path="./x",
            result=SCAN_RESULT,
        )


def test_list_scans_narrows_to_the_org_and_orders_newest_first(make_client):
    client, rec = make_client([_json([{"id": "scan-1"}])])
    assert list_scans(client, "user-jwt", "org-1") == [{"id": "scan-1"}]
    assert rec.last.url.params["org_id"] == "eq.org-1"
    assert rec.last.url.params["order"] == "started_at.desc"


def test_list_findings_filters_by_scan(make_client):
    client, rec = make_client([_json([{"check_id": "X"}])])
    assert list_findings(client, "user-jwt", "scan-1") == [{"check_id": "X"}]
    assert rec.last.url.params["scan_id"] == "eq.scan-1"
