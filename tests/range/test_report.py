"""Engagement report generation."""

from cloudnova.core.findings import Confidence, Finding, Location, Severity
from cloudnova.range.report import (
    Engagement,
    ReportFinding,
    engagement_from_dict,
    render_markdown,
)


def _rf(sev=Severity.HIGH, title="XSS"):
    return ReportFinding(
        title=title,
        severity=sev,
        affected="https://x/y",
        description="desc",
        remediation="fix it",
        impact="bad",
        steps=["step 1", "step 2"],
    )


def test_report_has_core_sections():
    md = render_markdown(Engagement("Client", "Tester", "*.x.com", findings=[_rf()]))
    for section in (
        "# Penetration Test Report",
        "## Executive summary",
        "## Methodology",
        "## Findings",
        "## Appendix",
    ):
        assert section in md


def test_findings_sorted_by_severity():
    e = Engagement(
        "C",
        "T",
        "scope",
        findings=[
            _rf(Severity.LOW, "low"),
            _rf(Severity.CRITICAL, "crit"),
            _rf(Severity.MEDIUM, "med"),
        ],
    )
    md = render_markdown(e)
    assert md.index("crit") < md.index("med") < md.index("low")


def test_executive_summary_counts():
    e = Engagement(
        "C", "T", "s", findings=[_rf(Severity.HIGH), _rf(Severity.HIGH), _rf(Severity.LOW)]
    )
    md = render_markdown(e)
    assert "2 high" in md and "1 low" in md


def test_from_scanner_finding():
    f = Finding(
        check_id="X",
        title="Public bucket",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=Location(path="main.tf", resource="aws_s3_bucket.data"),
        description="d",
        remediation="r",
        evidence="acl = public-read",
    )
    rf = ReportFinding.from_finding(f)
    assert rf.title == "Public bucket"
    assert rf.affected == "aws_s3_bucket.data"
    assert rf.steps == ["acl = public-read"]


def test_engagement_from_dict():
    data = {
        "engagement": {"client": "Acme", "tester": "me", "scope": "*.acme.com"},
        "findings": [
            {
                "title": "SQLi",
                "severity": "critical",
                "affected": "/login",
                "description": "d",
                "remediation": "params",
            }
        ],
    }
    e = engagement_from_dict(data)
    assert e.client == "Acme"
    assert e.findings[0].severity is Severity.CRITICAL
    md = render_markdown(e)
    assert "SQLi" in md


def test_engagement_requires_metadata():
    import pytest

    with pytest.raises(ValueError, match="engagement"):
        engagement_from_dict({"findings": []})


def test_empty_engagement_renders():
    md = render_markdown(Engagement("C", "T", "s"))
    assert "no findings" in md
