"""A transparent, explainable security-posture score.

The original thesis produced an "AI risk score" from a decision tree that had
collapsed to a single feature — a number nobody could explain. This replaces it
with an honest, documented formula: a weighted sum of findings by severity, plus
a penalty for each exploitable attack path, normalized to 0-100 (higher = worse)
and mapped to a letter grade.

Every input to the score is returned in the ``breakdown`` so a human — or an
agent — can see exactly why the number is what it is. No black box.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cloudnova.core.engine import ScanResult
from cloudnova.core.findings import Severity

# Points contributed per finding of each severity. Chosen so a single CRITICAL
# already lands in "poor" territory and low-severity noise can't dominate.
_SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

# An exploitable attack path is worse than the sum of its parts, so each one
# adds a flat penalty on top of the findings it's built from.
_ATTACK_PATH_PENALTY = 25

# Score is capped at 100; grades are cut points on the 0-100 scale.
_MAX_SCORE = 100
_GRADE_BANDS = [(10, "A"), (25, "B"), (50, "C"), (75, "D")]  # else "F"


@dataclass
class ScoreResult:
    """A posture score with a full breakdown of how it was computed."""

    score: int
    grade: str
    breakdown: dict[str, int] = field(default_factory=dict)


def _grade(score: int) -> str:
    for cutoff, letter in _GRADE_BANDS:
        if score <= cutoff:
            return letter
    return "F"


def posture_score(result: ScanResult) -> ScoreResult:
    """Compute a 0-100 risk posture score (higher = worse) with a breakdown."""
    breakdown: dict[str, int] = {}
    raw = 0
    # Attack paths are scored via their own penalty below, not also here, so they
    # aren't double-counted as CRITICAL findings.
    scored = [f for f in result.findings if f.check_id != "GRAPH_ATTACK_PATH"]
    for severity, weight in _SEVERITY_WEIGHTS.items():
        count = sum(1 for f in scored if f.severity is severity)
        if count:
            contribution = count * weight
            breakdown[severity.value] = contribution
            raw += contribution

    attack_paths = sum(1 for f in result.findings if f.check_id == "GRAPH_ATTACK_PATH")
    if attack_paths:
        penalty = attack_paths * _ATTACK_PATH_PENALTY
        breakdown["attack_paths"] = penalty
        raw += penalty

    score = min(raw, _MAX_SCORE)
    return ScoreResult(score=score, grade=_grade(score), breakdown=breakdown)
