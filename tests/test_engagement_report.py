"""The engagement report: the document a consultant hands a client.

This is the deliverable a services engagement is actually paid for, so the
tests are about whether it reads as a professional document, not whether a
template rendered.
"""

from __future__ import annotations

from pathlib import Path

from cloudnova.core.engine import Engine
from cloudnova.reporting.engagement import EngagementMeta, render_engagement


def _result(tmp_path: Path, content: str | None = None):
    (tmp_path / "main.tf").write_text(
        content
        or (
            'resource "aws_s3_bucket" "data" {\n  acl = "public-read"\n}\n'
            'resource "aws_db_instance" "billing" {\n  publicly_accessible = true\n}\n'
            'resource "aws_iam_policy" "p" {\n  policy = jsonencode({\n'
            '    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]\n'
            "  })\n}\n"
        ),
        encoding="utf-8",
    )
    return Engine().scan_path(tmp_path)


META = EngagementMeta(
    client="Acme GmbH",
    engagement="Cloud Infrastructure Security Assessment",
    scope="terraform/ in acme/infrastructure at commit 4f2a1b9",
    assessor="O. Abseh, Floatly Security",
)


# -- the document -----------------------------------------------------------


def test_report_is_self_contained(tmp_path):
    # It gets emailed, printed, and read on a plane. No external anything.
    html = render_engagement(_result(tmp_path), META)
    assert "http://" not in html
    assert "<script" not in html
    assert "cdn" not in html.lower()


def test_cover_names_the_client_and_the_assessor(tmp_path):
    html = render_engagement(_result(tmp_path), META)
    assert "Acme GmbH" in html
    assert "Cloud Infrastructure Security Assessment" in html
    assert "O. Abseh, Floatly Security" in html


def test_cover_carries_a_confidentiality_notice(tmp_path):
    # A client security report without one is a liability.
    html = render_engagement(_result(tmp_path), META)
    assert "Confidential" in html


def test_scope_is_stated_verbatim(tmp_path):
    # What was and was not examined is the first thing a dispute turns on.
    html = render_engagement(_result(tmp_path), META)
    assert "acme/infrastructure at commit 4f2a1b9" in html


def test_report_is_print_ready(tmp_path):
    html = render_engagement(_result(tmp_path), META)
    assert "@page" in html
    assert "page-break" in html


def test_html_is_escaped(tmp_path):
    hostile = EngagementMeta(
        client="<script>alert(1)</script>",
        engagement="x",
        scope="y",
        assessor="z",
    )
    html = render_engagement(_result(tmp_path), hostile)
    assert "<script>alert(1)</script>" not in html


# -- executive summary ------------------------------------------------------


def test_summary_leads_with_a_grade_and_a_verdict(tmp_path):
    html = render_engagement(_result(tmp_path), META)
    assert "Executive summary" in html
    # A letter grade, a score, and prose a non-engineer can act on.
    assert "/ 100" in html
    assert "Risk posture" in html


def test_summary_counts_every_severity_present(tmp_path):
    result = _result(tmp_path)
    html = render_engagement(result, META)
    for finding in result.findings:
        assert finding.severity.value in html


def test_a_clean_estate_reads_as_clean_not_as_empty(tmp_path):
    # The most awkward report to write is the one with nothing in it.
    result = _result(
        tmp_path,
        'resource "aws_s3_bucket" "b" {\n  acl = "private"\n'
        "  server_side_encryption_configuration {}\n"
        "  versioning { enabled = true }\n}\n",
    )
    html = render_engagement(result, META)
    assert "no findings" in html.lower() or "No issues" in html
    assert "Executive summary" in html


# -- findings ---------------------------------------------------------------


def test_every_finding_appears_with_its_remediation(tmp_path):
    import html as html_mod

    result = _result(tmp_path)
    page = render_engagement(result, META)
    assert result.findings
    for finding in result.findings:
        assert html_mod.escape(finding.title, quote=True) in page
        # Escaped, because the report escapes everything it renders.
        assert html_mod.escape(finding.remediation[:40], quote=True) in page


def test_findings_carry_their_framework_mapping(tmp_path):
    result = _result(tmp_path)
    html = render_engagement(result, META)
    mapped = [f for f in result.findings if f.cis_controls or f.mitre_attack]
    assert mapped, "fixture should produce at least one mapped finding"
    for finding in mapped:
        for control in finding.cis_controls + finding.mitre_attack:
            assert control in html


def test_confidence_is_shown_alongside_severity(tmp_path):
    # The whole honesty argument collapses if the report hides confidence.
    html = render_engagement(_result(tmp_path), META)
    assert "Confidence" in html


def test_findings_are_ordered_most_severe_first(tmp_path):
    result = _result(tmp_path)
    html = render_engagement(result, META)
    positions = []
    for finding in result.sorted_findings():
        pos = html.find(finding.title)
        if pos >= 0:
            positions.append(pos)
    assert positions == sorted(positions)


# -- methodology and appendix ----------------------------------------------


def test_methodology_explains_severity_versus_confidence(tmp_path):
    html = render_engagement(_result(tmp_path), META)
    assert "Methodology" in html
    assert "confidence" in html.lower()


def test_compliance_appendix_names_the_standards_properly(tmp_path):
    # "ISO27001" would read as sloppy in a document a client paid for.
    page = render_engagement(_result(tmp_path), META)
    assert "ISO/IEC 27001" in page
    assert "PCI DSS" in page
    assert "CIS Controls v8" in page
    assert "compliance mapping" in page
    # And it must not overclaim.
    assert "not a certification" in page


def test_attack_paths_get_their_own_section_when_present(tmp_path):
    # Paths are the finding type a client cares about most, so they lead.
    result = _result(tmp_path)
    html = render_engagement(result, META)
    assert "Key risks" in html or "Attack path" in html
