"""Pure web-assessment checks: findings fire on weak config, stay quiet on strong."""

from cloudnova.core.findings import Severity
from cloudnova.range.webassess import analyze
from cloudnova.range.webassess.checks import (
    check_cookies,
    check_cors,
    check_security_headers,
    check_server_disclosure,
    check_transport,
    exposed_path_findings,
)
from cloudnova.range.webassess.model import HttpSnapshot

HARDENED = HttpSnapshot(
    url="https://ex.com",
    status=200,
    headers={
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Server": "nginx",
    },
    cookies=["sid=abc; Secure; HttpOnly; SameSite=Lax"],
    final_url="https://ex.com",
    tls=True,
)


def test_hardened_site_is_clean():
    assert analyze(HARDENED) == []


def test_missing_headers_flagged():
    snap = HttpSnapshot(url="https://ex.com", status=200, headers={}, tls=True)
    ids = {f.id for f in check_security_headers(snap)}
    assert "WEB_HEADER_CONTENT_SECURITY_POLICY" in ids
    assert "WEB_HEADER_STRICT_TRANSPORT_SECURITY" in ids


def test_hsts_not_flagged_on_plain_http():
    snap = HttpSnapshot(url="http://ex.com", status=200, headers={}, tls=False)
    ids = {f.id for f in check_security_headers(snap)}
    assert "WEB_HEADER_STRICT_TRANSPORT_SECURITY" not in ids  # HSTS is TLS-only


def test_plaintext_transport_flagged():
    snap = HttpSnapshot(url="http://ex.com", status=200, final_url="http://ex.com", tls=False)
    out = check_transport(snap)
    assert out and out[0].id == "WEB_NO_TLS" and out[0].severity is Severity.HIGH


def test_http_redirecting_to_https_is_ok():
    snap = HttpSnapshot(url="http://ex.com", status=301, final_url="https://ex.com", tls=True)
    assert check_transport(snap) == []


def test_version_disclosure():
    snap = HttpSnapshot(
        url="https://ex.com", status=200, headers={"Server": "Apache/2.4.49"}, tls=True
    )
    out = check_server_disclosure(snap)
    assert out and "2.4.49" in out[0].detail


def test_no_version_no_finding():
    snap = HttpSnapshot(url="https://ex.com", status=200, headers={"Server": "nginx"}, tls=True)
    assert check_server_disclosure(snap) == []


def test_cors_wildcard_with_credentials_is_high():
    snap = HttpSnapshot(
        url="https://ex.com",
        status=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
        tls=True,
    )
    out = check_cors(snap)
    assert out and out[0].severity is Severity.HIGH


def test_cors_specific_origin_is_ok():
    snap = HttpSnapshot(
        url="https://ex.com",
        status=200,
        headers={"Access-Control-Allow-Origin": "https://trusted.com"},
        tls=True,
    )
    assert check_cors(snap) == []


def test_cookie_missing_flags():
    snap = HttpSnapshot(url="https://ex.com", status=200, cookies=["sid=x"], tls=True)
    out = check_cookies(snap)
    assert out and "Secure" in out[0].title and "HttpOnly" in out[0].title


def test_cookie_fully_flagged_is_ok():
    snap = HttpSnapshot(
        url="https://ex.com",
        status=200,
        cookies=["sid=x; Secure; HttpOnly; SameSite=Strict"],
        tls=True,
    )
    assert check_cookies(snap) == []


def test_exposed_path_findings():
    out = exposed_path_findings([".git/HEAD", ".env"])
    assert len(out) == 2
    assert all(f.id == "WEB_EXPOSED_SENSITIVE_PATH" for f in out)


def test_header_lookup_is_case_insensitive():
    snap = HttpSnapshot(url="https://ex.com", status=200, headers={"SeRvEr": "nginx"}, tls=True)
    assert snap.header("server") == "nginx"
