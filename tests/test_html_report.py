"""HTML report: self-contained, escaped, and structurally sound."""

from cloudnova.core.engine import ScanResult
from cloudnova.core.findings import Confidence, Finding, Location, Severity
from cloudnova.reporting import render_html


def _f(sev=Severity.HIGH, title="t", desc="d"):
    return Finding(
        check_id="X",
        title=title,
        severity=sev,
        confidence=Confidence.HIGH,
        location=Location(path="p", resource="r"),
        description=desc,
        remediation="fix",
    )


def test_html_is_self_contained():
    out = render_html(ScanResult(findings=[_f()]))
    assert out.startswith("<!doctype html>")
    # No external resources -> works offline, no data leak to a CDN.
    assert "http://" not in out
    assert "https://" not in out


def test_html_escapes_finding_content():
    malicious = _f(title="<script>alert(1)</script>", desc="<img src=x>")
    out = render_html(ScanResult(findings=[malicious]))
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_html_shows_grade_and_counts():
    out = render_html(ScanResult(findings=[_f(Severity.CRITICAL)], files_scanned=2, checks_run=5))
    assert "2 file(s)" in out
    assert "5 check(s)" in out
    assert ">C<" in out  # a single critical -> grade C


def test_html_empty_scan():
    out = render_html(ScanResult())
    assert "No findings" in out
    assert ">A<" in out
