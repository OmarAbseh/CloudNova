"""Scan diff: introduced / fixed / unchanged by stable fingerprint."""

from cloudnova.diff import diff_findings, diff_reports, fingerprint


def _f(check_id, path="main.tf", resource="r", evidence="e", severity="high"):
    return {
        "check_id": check_id,
        "severity": severity,
        "title": f"{check_id} title",
        "evidence": evidence,
        "location": {"path": path, "resource": resource},
    }


def test_fingerprint_stable_and_distinct():
    assert fingerprint(_f("A")) == fingerprint(_f("A"))
    assert fingerprint(_f("A")) != fingerprint(_f("B"))


def test_introduced_and_fixed():
    old = [_f("A"), _f("B")]
    new = [_f("A"), _f("C")]  # B fixed, C introduced, A unchanged
    d = diff_findings(old, new)
    assert {f["check_id"] for f in d.introduced} == {"C"}
    assert {f["check_id"] for f in d.fixed} == {"B"}
    assert d.unchanged == 1


def test_introduced_sorted_by_severity():
    old: list = []
    new = [_f("low1", severity="low"), _f("crit1", severity="critical")]
    d = diff_findings(old, new)
    assert d.introduced[0]["check_id"] == "crit1"


def test_score_delta():
    d = diff_findings([], [], old_score=10, new_score=40)
    assert d.score_delta == 30  # worse


def test_diff_reports_reads_summary():
    old = {"summary": {"posture_score": 20}, "findings": [_f("A")]}
    new = {"summary": {"posture_score": 60}, "findings": [_f("A"), _f("B")]}
    d = diff_reports(old, new)
    assert d.score_delta == 40
    assert {f["check_id"] for f in d.introduced} == {"B"}
