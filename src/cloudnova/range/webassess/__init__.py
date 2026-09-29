"""Authorized, non-destructive web assessment for CloudNova Range.

A passive posture scanner for web targets: it authorizes every target through the
scope engine first, then makes benign read-only requests and reports missing
security headers, weak cookies, permissive CORS, plaintext transport, version
disclosure, and reachable sensitive paths. It never sends payloads, guesses
credentials, or exploits anything — the operator stays in the loop for anything
beyond passive assessment.
"""

from cloudnova.range.webassess.checks import analyze
from cloudnova.range.webassess.model import HttpSnapshot, WebAssessment, WebFinding
from cloudnova.range.webassess.probe import NotAuthorizedError, ProbeError
from cloudnova.range.webassess.runner import assess

__all__ = [
    "HttpSnapshot",
    "NotAuthorizedError",
    "ProbeError",
    "WebAssessment",
    "WebFinding",
    "analyze",
    "assess",
]
