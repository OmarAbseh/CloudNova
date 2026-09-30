"""Active vulnerability *detection* — opt-in, scope-gated, non-destructive.

This is real DAST, the same category as OWASP ZAP's active scan or Nuclei: it
sends a crafted-but-safe probe to a query parameter and inspects the response to
*confirm a bug exists*, using read-only requests. Every function authorizes the
target through the scope engine first (via :mod:`probe`), and the caller opts in
explicitly.

The detection primitives (`body_reflects_marker`, `sql_error_signature`,
`body_reads_passwd`) are pure functions so the logic is testable offline.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cloudnova.range.scope import Scope
from cloudnova.range.webassess.probe import ProbeError, get_body

# A unique, benign marker with an HTML tag. If it comes back verbatim (unencoded)
# the parameter reflects input without output-encoding => reflected XSS.
XSS_MARKER = "cn0va7z<b>xss</b>"

# Signatures of a database error leaking through — the classic SQLi tell.
_SQL_ERRORS = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate[",
    "ora-01756",
    "ora-00933",
    "psql: error",
    "pg::syntaxerror",
    "sqlite3::",
    "odbc sql server driver",
)

# A safe, breaking token: a lone quote provokes a DB syntax error if unsanitized.
SQL_PROBE = "'"

# Canonical traversal payload; success is the /etc/passwd signature coming back.
TRAVERSAL_PROBE = "../../../../../../etc/passwd"
_PASSWD_RE = re.compile(r"root:.*:0:0:")


def body_reflects_marker(body: str) -> bool:
    return XSS_MARKER in body


def sql_error_signature(body: str) -> str | None:
    low = body.lower()
    for sig in _SQL_ERRORS:
        if sig in low:
            return sig
    return None


def body_reads_passwd(body: str) -> bool:
    return bool(_PASSWD_RE.search(body))


def _params(url: str) -> list[tuple[str, str]]:
    return parse_qsl(urlparse(url).query, keep_blank_values=True)


def _with_param(url: str, name: str, value: str) -> str:
    parts = urlparse(url)
    params = [(k, value if k == name else v) for k, v in _params(url)]
    return urlunparse(parts._replace(query=urlencode(params)))


def _probe_each_param(url: str, scope: Scope, payload: str, detector) -> list[str]:  # type: ignore[no-untyped-def]
    """Inject ``payload`` into each query parameter; return params the detector flags."""
    hits: list[str] = []
    for name, _ in _params(url):
        target = _with_param(url, name, payload)
        try:
            _status, body = get_body(target, scope)
        except ProbeError:
            continue
        if detector(body):
            hits.append(name)
    return hits


def detect_reflected_xss(url: str, scope: Scope) -> list[str]:
    """Query params whose value is reflected unencoded (reflected XSS)."""
    return _probe_each_param(url, scope, XSS_MARKER, body_reflects_marker)


def detect_sql_injection(url: str, scope: Scope) -> list[str]:
    """Query params that leak a database error when sent a breaking token."""
    return _probe_each_param(
        url, scope, SQL_PROBE, lambda body: sql_error_signature(body) is not None
    )


def detect_path_traversal(url: str, scope: Scope) -> list[str]:
    """Query params that return the /etc/passwd signature for a traversal payload."""
    return _probe_each_param(url, scope, TRAVERSAL_PROBE, body_reads_passwd)
