"""Transparent posture score: every input to the number is in the breakdown."""

from cloudnova.core.engine import ScanResult
from cloudnova.core.findings import Confidence, Finding, Location, Severity
from cloudnova.scoring import posture_score


def _f(sev: Severity, cid: str = "X") -> Finding:
    return Finding(
        check_id=cid,
        title="t",
        severity=sev,
        confidence=Confidence.HIGH,
        location=Location(path="p"),
        description="d",
        remediation="r",
    )


def test_empty_scan_scores_zero_grade_a():
    score = posture_score(ScanResult())
    assert score.score == 0
    assert score.grade == "A"


def test_single_low_is_grade_a():
    score = posture_score(ScanResult(findings=[_f(Severity.LOW)]))
    assert score.score == 2
    assert score.grade == "A"


def test_single_critical_is_severe():
    score = posture_score(ScanResult(findings=[_f(Severity.CRITICAL)]))
    assert score.score == 40
    assert score.grade == "C"
    assert score.breakdown["critical"] == 40


def test_score_capped_at_100():
    score = posture_score(ScanResult(findings=[_f(Severity.CRITICAL) for _ in range(10)]))
    assert score.score == 100
    assert score.grade == "F"


def test_attack_path_not_double_counted():
    # A GRAPH_ATTACK_PATH finding scores via the penalty only, not also as critical.
    result = ScanResult(findings=[_f(Severity.CRITICAL, "GRAPH_ATTACK_PATH")])
    score = posture_score(result)
    assert "critical" not in score.breakdown
    assert score.breakdown["attack_paths"] == 25
    assert score.score == 25


def test_breakdown_sums_to_score_when_uncapped():
    result = ScanResult(findings=[_f(Severity.HIGH), _f(Severity.MEDIUM), _f(Severity.LOW)])
    score = posture_score(result)
    assert sum(score.breakdown.values()) == score.score == 20 + 8 + 2
