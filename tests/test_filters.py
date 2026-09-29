"""Severity filtering keeps only findings at or above a threshold."""

from cloudnova.core.engine import ScanResult, filter_by_severity
from cloudnova.core.findings import Confidence, Finding, Location, Severity


def _f(sev: Severity, cid: str) -> Finding:
    return Finding(
        check_id=cid,
        title="t",
        severity=sev,
        confidence=Confidence.HIGH,
        location=Location(path="p"),
        description="d",
        remediation="r",
    )


def _result() -> ScanResult:
    return ScanResult(
        findings=[
            _f(Severity.CRITICAL, "A"),
            _f(Severity.HIGH, "B"),
            _f(Severity.MEDIUM, "C"),
            _f(Severity.LOW, "D"),
            _f(Severity.INFO, "E"),
        ],
        files_scanned=3,
        checks_run=10,
        errors=["boom"],
    )


def test_filter_high_keeps_critical_and_high():
    filtered = filter_by_severity(_result(), Severity.HIGH)
    assert {f.check_id for f in filtered.findings} == {"A", "B"}


def test_filter_preserves_metadata():
    filtered = filter_by_severity(_result(), Severity.CRITICAL)
    assert filtered.files_scanned == 3
    assert filtered.checks_run == 10
    assert filtered.errors == ["boom"]


def test_filter_info_keeps_everything():
    filtered = filter_by_severity(_result(), Severity.INFO)
    assert len(filtered.findings) == 5


def test_filter_does_not_mutate_original():
    original = _result()
    filter_by_severity(original, Severity.CRITICAL)
    assert len(original.findings) == 5
