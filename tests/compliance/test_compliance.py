"""Compliance mapping: categories, control status, coverage-honest score."""

from cloudnova.compliance import Framework, assess, assess_all, categorize
from cloudnova.compliance.engine import ControlState
from cloudnova.compliance.frameworks import Category


def test_categorize():
    assert categorize("AWS_S3_PUBLIC") is Category.EXPOSURE
    assert categorize("AWS_S3_NO_ENCRYPTION") is Category.ENCRYPTION
    assert categorize("AWS_IAM_NO_MFA") is Category.IDENTITY
    assert categorize("CT_CLOUDTRAIL_DISABLED") is Category.LOGGING
    assert categorize("IAC_HARDCODED_SECRET") is Category.SECRETS
    assert categorize("SOME_RANDOM_CHECK") is Category.OTHER


def test_exposure_finding_fails_network_control():
    report = assess(["AWS_S3_PUBLIC"], Framework.ISO_27001)
    a820 = next(c for c in report.controls if c.control_id == "A.8.20")
    assert a820.state is ControlState.FAIL
    assert "AWS_S3_PUBLIC" in a820.failing_checks


def test_clean_scan_all_assessed_controls_pass():
    report = assess([], Framework.NIST_CSF)
    # Nothing failed, but the controls we assess should be PASS (not falsely green).
    assert report.failed == []
    assert report.passed  # at least some assessed controls
    assert report.score == 100


def test_score_is_coverage_honest():
    # A control we never assess stays NOT_ASSESSED and is excluded from the score.
    report = assess([], Framework.ISO_27001)
    states = {c.control_id: c.state for c in report.controls}
    # every control is either PASS or NOT_ASSESSED here (nothing failed)
    assert all(s in (ControlState.PASS, ControlState.NOT_ASSESSED) for s in states.values())
    assert len(report.assessed) <= len(report.controls)


def test_identity_finding_fails_pci_req8():
    report = assess(["AWS_IAM_NO_MFA"], Framework.PCI_DSS)
    req8 = next(c for c in report.controls if c.control_id == "Req.8")
    assert req8.state is ControlState.FAIL


def test_assess_all_covers_every_framework():
    reports = assess_all(["AWS_S3_PUBLIC", "AWS_IAM_NO_MFA"])
    assert set(reports) == set(Framework)
    for report in reports.values():
        assert report.failed  # both an exposure and identity finding fail something


def test_soc2_and_cis_frameworks_present():
    from cloudnova.compliance import Framework

    reports = assess_all(["AWS_S3_PUBLIC", "AWS_IAM_NO_MFA", "CFN_S3_NO_ENCRYPTION"])
    assert Framework.SOC_2 in reports
    assert Framework.CIS_V8 in reports
    soc2 = reports[Framework.SOC_2]
    # exposure + identity + encryption findings should fail several SOC 2 controls
    assert soc2.failed
    cis = reports[Framework.CIS_V8]
    assert any(c.control_id == "CIS.6" for c in cis.failed) or cis.failed


def test_soc2_encryption_maps_to_cc67():
    from cloudnova.compliance import Framework

    report = assess(["AWS_S3_NO_ENCRYPTION"], Framework.SOC_2)
    cc67 = next(c for c in report.controls if c.control_id == "CC6.7")
    assert cc67.state.value == "FAIL"


def test_render_markdown_report():
    from cloudnova.compliance import assess_all
    from cloudnova.compliance.report import render_markdown

    reports = assess_all(["AWS_S3_PUBLIC", "AWS_IAM_NO_MFA"])
    md = render_markdown(reports, target="infra", client="Acme")
    assert "# Compliance Report" in md and "Acme" in md
    assert "ISO/IEC 27001" in md and "SOC 2" in md
    assert "Summary" in md
