"""Run the blackbox checklist against one authorized target.

Authorization is the only gate and is checked first. Automatable items are
resolved from a single passive web assessment (headers, cookies, CORS, transport,
metafiles, backup/admin paths, HTTP methods). Manual items are returned as TODO
with their methodology, for the operator to perform.
"""

from __future__ import annotations

from cloudnova.range.checklist.blackbox import (
    ADMIN_PATHS,
    BLACKBOX_CHECKLIST,
    METAFILES,
)
from cloudnova.range.checklist.model import ChecklistRun, Mode, RunItem, State
from cloudnova.range.scope import Scope
from cloudnova.range.webassess.active import (
    detect_path_traversal,
    detect_reflected_xss,
    detect_sql_injection,
)
from cloudnova.range.webassess.checks import COMMON_SENSITIVE_PATHS, analyze
from cloudnova.range.webassess.model import HttpSnapshot
from cloudnova.range.webassess.probe import (
    NotAuthorizedError,
    ProbeError,
    fetch,
    find_exposed_paths,
    risky_methods,
)


def _attestation(scope: Scope) -> str:
    a = scope.authorization
    ref = f" (ref {a.reference})" if a.reference else ""
    return f"{a.program} - authorized by {a.authorized_by}{ref}"


def _fail_or_pass(condition: bool, evidence: str = "") -> tuple[State, list[str]]:
    if condition:
        return State.FAIL, [evidence] if evidence else []
    return State.PASS, []


def run_checklist(url: str, scope: Scope, *, active: bool = False) -> ChecklistRun:
    """Run the blackbox checklist against an authorized URL.

    ``active=True`` opts in to intrusive *detection* (reflected XSS, SQL errors,
    path traversal) - still scope-gated and non-destructive. Off by default.
    """
    from urllib.parse import urlparse

    host = urlparse(url).hostname or url
    decision = scope.authorize(host)
    if not decision.allowed:
        return ChecklistRun(target=host, authorized=False, attestation=decision.reason)

    attestation = _attestation(scope)
    try:
        snapshot = fetch(url, scope)
    except (NotAuthorizedError, ProbeError) as exc:
        # Unreachable/denied: every automatable item becomes a manual TODO.
        run = ChecklistRun(target=host, authorized=True, attestation=attestation)
        for item in BLACKBOX_CHECKLIST:
            run.items.append(RunItem(item, State.TODO, [f"not auto-checked: {exc}"]))
        return run

    auto = _resolve_auto(url, scope, snapshot)
    active_results = _resolve_active(url, scope) if active else {}

    run = ChecklistRun(target=host, authorized=True, attestation=attestation)
    for item in BLACKBOX_CHECKLIST:
        if item.mode is Mode.AUTO and item.id in auto:
            state, evidence = auto[item.id]
            run.items.append(RunItem(item, state, evidence))
        elif item.mode is Mode.ACTIVE and item.id in active_results:
            state, evidence = active_results[item.id]
            run.items.append(RunItem(item, state, evidence))
        elif item.mode is Mode.ACTIVE:
            run.items.append(
                RunItem(item, State.TODO, ["Intrusive - re-run with --active to auto-detect"])
            )
        else:
            run.items.append(RunItem(item, State.TODO, [f"Manual: {item.description}"]))
    return run


def _resolve_active(url: str, scope: Scope) -> dict[str, tuple[State, list[str]]]:
    """Run opt-in active *detection* and map it onto the ACTIVE checklist items."""
    xss = detect_reflected_xss(url, scope)
    sqli = detect_sql_injection(url, scope)
    traversal = detect_path_traversal(url, scope)
    return {
        "INPV-001": _fail_or_pass(bool(xss), f"Reflected (unencoded) params: {', '.join(xss)}"),
        "INPV-005": _fail_or_pass(bool(sqli), f"DB error from params: {', '.join(sqli)}"),
        "ATHZ-001": _fail_or_pass(
            bool(traversal), f"Traversal signature from params: {', '.join(traversal)}"
        ),
    }


def _resolve_auto(
    url: str, scope: Scope, snapshot: HttpSnapshot
) -> dict[str, tuple[State, list[str]]]:
    """Map passive observations onto the automatable checklist items."""
    findings = {f.id: f for f in analyze(snapshot)}
    exposed = find_exposed_paths(url, scope, COMMON_SENSITIVE_PATHS)
    metafiles = find_exposed_paths(url, scope, METAFILES)
    admin = find_exposed_paths(url, scope, ADMIN_PATHS)
    risky = risky_methods(url, scope)

    server = snapshot.header("server") or "not disclosed"
    powered = snapshot.header("x-powered-by") or "not disclosed"

    out: dict[str, tuple[State, list[str]]] = {
        "INFO-002": (State.INFO, [f"Server banner: {server}"]),
        "INFO-008": (State.INFO, [f"X-Powered-By: {powered}"]),
        "INFO-003": (
            State.INFO,
            [f"Metafiles present: {', '.join(metafiles)}"] if metafiles else ["No metafiles found"],
        ),
        "CONF-007": _fail_or_pass(
            "WEB_HEADER_STRICT_TRANSPORT_SECURITY" in findings, "HSTS header missing"
        ),
        "CONF-008": _fail_or_pass(
            "WEB_CORS_WILDCARD" in findings,
            findings["WEB_CORS_WILDCARD"].detail if "WEB_CORS_WILDCARD" in findings else "",
        ),
        "ATHN-001": _fail_or_pass("WEB_NO_TLS" in findings, "Served over plaintext HTTP"),
        "CLNT-009": _fail_or_pass(
            "WEB_HEADER_X_FRAME_OPTIONS" in findings, "No clickjacking protection header"
        ),
        "CONF-004": _fail_or_pass(
            bool(exposed), f"Reachable sensitive files: {', '.join(exposed)}"
        ),
        "CONF-002": _fail_or_pass(
            bool(admin), f"Reachable admin/default pages: {', '.join(admin)}"
        ),
        "CONF-005": _fail_or_pass(bool(admin), f"Reachable admin interfaces: {', '.join(admin)}"),
        "CONF-006": _fail_or_pass(
            bool(risky), f"Risky HTTP methods enabled: {', '.join(sorted(risky))}"
        ),
    }

    # SESS-002 is N/A when the target sets no cookies.
    if not snapshot.cookies:
        out["SESS-002"] = (State.NA, ["No cookies set"])
    else:
        out["SESS-002"] = _fail_or_pass(
            "WEB_COOKIE_FLAGS" in findings, "Session cookie missing Secure/HttpOnly/SameSite"
        )
    return out
