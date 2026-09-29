"""Pure analysis over an :class:`HttpSnapshot`.

Every function takes a snapshot and returns findings — no I/O, no network, no
mutation. This is what makes the assessment testable offline and deterministic.
All of it is passive: it reasons about what a single benign request returned. It
never sends a payload, guesses a credential, or tries to exploit anything.
"""

from __future__ import annotations

from collections.abc import Iterable

from cloudnova.core.findings import Confidence, Severity
from cloudnova.range.webassess.model import HttpSnapshot, WebFinding

# Security response headers that a hardened site should set, with why they matter.
_SECURITY_HEADERS: dict[str, tuple[str, Severity, str]] = {
    "strict-transport-security": (
        "HSTS not set",
        Severity.MEDIUM,
        "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains' so "
        "browsers refuse to talk to the site over plaintext HTTP.",
    ),
    "content-security-policy": (
        "Content-Security-Policy not set",
        Severity.MEDIUM,
        "Define a CSP to constrain script/style sources; it is the strongest "
        "in-browser defense against cross-site scripting (XSS).",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options not set",
        Severity.LOW,
        "Set 'X-Content-Type-Options: nosniff' to stop MIME-type sniffing.",
    ),
    "x-frame-options": (
        "Clickjacking protection missing",
        Severity.MEDIUM,
        "Set 'X-Frame-Options: DENY' (or a frame-ancestors CSP) to prevent the "
        "page being framed for clickjacking.",
    ),
    "referrer-policy": (
        "Referrer-Policy not set",
        Severity.LOW,
        "Set 'Referrer-Policy: strict-origin-when-cross-origin' to avoid leaking "
        "full URLs to third parties.",
    ),
}

# Sensitive files that should never be world-readable if the server exposes them.
COMMON_SENSITIVE_PATHS: tuple[str, ...] = (
    ".git/HEAD",
    ".env",
    ".DS_Store",
    "backup.zip",
    "config.php.bak",
    "wp-config.php.bak",
    ".svn/entries",
    "phpinfo.php",
)


def check_security_headers(snap: HttpSnapshot) -> list[WebFinding]:
    """Report missing hardening headers. Framed as findings, not exploits."""
    findings: list[WebFinding] = []
    for header, (title, severity, fix) in _SECURITY_HEADERS.items():
        # HSTS only matters over TLS; skip it for plain-HTTP snapshots.
        if header == "strict-transport-security" and not snap.tls:
            continue
        if snap.header(header) is None:
            findings.append(
                WebFinding(
                    id=f"WEB_HEADER_{header.upper().replace('-', '_')}",
                    title=title,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    detail=f"{snap.url} did not return the '{header}' response header.",
                    remediation=fix,
                )
            )
    return findings


def check_transport(snap: HttpSnapshot) -> list[WebFinding]:
    """Plaintext HTTP that does not upgrade to HTTPS is a confidentiality risk."""
    if snap.tls:
        return []
    upgraded = snap.final_url.lower().startswith("https://")
    if upgraded:
        return []
    return [
        WebFinding(
            id="WEB_NO_TLS",
            title="Site served over plaintext HTTP",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            detail=f"{snap.url} responded over HTTP without redirecting to HTTPS.",
            remediation="Serve exclusively over HTTPS and 301-redirect all HTTP to HTTPS.",
        )
    ]


def check_server_disclosure(snap: HttpSnapshot) -> list[WebFinding]:
    """A Server/X-Powered-By header exposing a version aids targeted exploitation."""
    findings: list[WebFinding] = []
    for header in ("server", "x-powered-by"):
        value = snap.header(header)
        # Flag only when a version number is disclosed (contains a digit).
        if value and any(ch.isdigit() for ch in value):
            findings.append(
                WebFinding(
                    id=f"WEB_VERSION_DISCLOSURE_{header.upper().replace('-', '_')}",
                    title="Software version disclosed in headers",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    detail=f"'{header}: {value}' reveals a specific version to attackers.",
                    remediation=f"Suppress or genericize the '{header}' header.",
                )
            )
    return findings


def check_cors(snap: HttpSnapshot) -> list[WebFinding]:
    """A wildcard ACAO combined with credentials is a data-exposure risk."""
    acao = snap.header("access-control-allow-origin")
    if acao != "*":
        return []
    creds = (snap.header("access-control-allow-credentials") or "").lower() == "true"
    severity = Severity.HIGH if creds else Severity.MEDIUM
    extra = " with credentials allowed" if creds else ""
    return [
        WebFinding(
            id="WEB_CORS_WILDCARD",
            title="Permissive CORS policy",
            severity=severity,
            confidence=Confidence.HIGH,
            detail=f"{snap.url} returns 'Access-Control-Allow-Origin: *'{extra}.",
            remediation="Reflect only an allow-list of trusted origins; never pair "
            "'*' with 'Access-Control-Allow-Credentials: true'.",
        )
    ]


def _parse_cookie_flags(cookie: str) -> set[str]:
    return {part.strip().lower() for part in cookie.split(";") if part.strip()}


def check_cookies(snap: HttpSnapshot) -> list[WebFinding]:
    """Session cookies without Secure/HttpOnly/SameSite are hijack/CSRF risks."""
    findings: list[WebFinding] = []
    for cookie in snap.cookies:
        name = cookie.split("=", 1)[0].strip()
        flags = _parse_cookie_flags(cookie)
        missing = []
        if not any(f == "secure" for f in flags):
            missing.append("Secure")
        if not any(f == "httponly" for f in flags):
            missing.append("HttpOnly")
        if not any(f.startswith("samesite") for f in flags):
            missing.append("SameSite")
        if missing:
            findings.append(
                WebFinding(
                    id="WEB_COOKIE_FLAGS",
                    title=f"Cookie '{name}' missing {', '.join(missing)}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    detail=f"Set-Cookie for '{name}' is missing: {', '.join(missing)}.",
                    remediation="Set Secure, HttpOnly, and an explicit SameSite on "
                    "session cookies.",
                )
            )
    return findings


def exposed_path_findings(paths: Iterable[str]) -> list[WebFinding]:
    """Turn a list of reachable sensitive paths into findings."""
    findings: list[WebFinding] = []
    for path in paths:
        findings.append(
            WebFinding(
                id="WEB_EXPOSED_SENSITIVE_PATH",
                title=f"Sensitive path reachable: {path}",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                detail=f"A request for '{path}' returned a success status.",
                remediation=f"Remove '{path}' from the web root or block it at the server.",
            )
        )
    return findings


# All snapshot-only checks, run by the orchestrator.
SNAPSHOT_CHECKS = (
    check_transport,
    check_security_headers,
    check_server_disclosure,
    check_cors,
    check_cookies,
)


def analyze(snap: HttpSnapshot) -> list[WebFinding]:
    """Run every passive snapshot check and collect the findings."""
    findings: list[WebFinding] = []
    for check in SNAPSHOT_CHECKS:
        findings.extend(check(snap))
    return findings
