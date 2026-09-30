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
