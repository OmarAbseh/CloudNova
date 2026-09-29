"""Orchestrate an authorized, non-destructive web assessment of one target.

Authorization is checked first and is the only gate: an out-of-scope target
yields an unauthorized result and never touches the network. In-scope targets get
a single passive snapshot plus a small sensitive-path check, analyzed by the pure
functions in :mod:`checks`.
"""

from __future__ import annotations

from cloudnova.range.scope import Scope
from cloudnova.range.webassess.checks import analyze, exposed_path_findings
from cloudnova.range.webassess.model import WebAssessment
from cloudnova.range.webassess.probe import (
    NotAuthorizedError,
    ProbeError,
    fetch,
    find_exposed_paths,
)


def assess(url: str, scope: Scope, *, check_paths: bool = True) -> WebAssessment:
    """Assess an authorized web target. Returns findings, never raises on scope."""
    host = url
    decision = scope.authorize(_host(url))
    if not decision.allowed:
        return WebAssessment(target=host, authorized=False, reason=decision.reason)

    try:
        snapshot = fetch(url, scope)
    except NotAuthorizedError as exc:
        return WebAssessment(target=host, authorized=False, reason=str(exc))
    except ProbeError as exc:
        return WebAssessment(target=host, authorized=True, reason=f"unreachable: {exc}")

    findings = analyze(snapshot)
    exposed: list[str] = []
    if check_paths:
        try:
            exposed = find_exposed_paths(url, scope)
        except (NotAuthorizedError, ProbeError):
            exposed = []
    findings.extend(exposed_path_findings(exposed))

    findings.sort(key=lambda f: f.severity.rank, reverse=True)
    return WebAssessment(
        target=host,
        authorized=True,
        reason=decision.reason,
        findings=findings,
        exposed_paths=exposed,
    )


def _host(url: str) -> str:
    from urllib.parse import urlparse

    return urlparse(url).hostname or url
