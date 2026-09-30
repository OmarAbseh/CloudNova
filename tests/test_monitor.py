"""Scan history + drift detection."""

from cloudnova import monitor


def _report(findings, score=50):
    return {
        "summary": {"posture_score": score, "grade": "C", "findings": len(findings)},
        "findings": findings,
    }


def _f(check_id, path="a.tf"):
    return {"check_id": check_id, "title": check_id, "severity": "high", "location": {"path": path}}


def test_first_run_has_no_drift(tmp_path):
    rep = _report([_f("TF_S3_PUBLIC_ACL")])
    assert monitor.diff_against_latest("proj", rep, data_dir=str(tmp_path)) is None


def test_records_and_detects_new_finding(tmp_path):
    dd = str(tmp_path)
    monitor.record_scan("proj", _report([_f("A")]), data_dir=dd)
    drift = monitor.diff_against_latest("proj", _report([_f("A"), _f("B")]), data_dir=dd)
    assert drift is not None
    ids = {f["check_id"] for f in drift.introduced}
    assert ids == {"B"}
    assert drift.unchanged == 1


def test_detects_fixed_finding(tmp_path):
    dd = str(tmp_path)
    monitor.record_scan("proj", _report([_f("A"), _f("B")]), data_dir=dd)
    drift = monitor.diff_against_latest("proj", _report([_f("A")]), data_dir=dd)
    assert drift is not None
    assert {f["check_id"] for f in drift.fixed} == {"B"}


def test_trend_tracks_score(tmp_path):
    dd = str(tmp_path)
    monitor.record_scan("proj", _report([_f("A")], score=70), data_dir=dd)
    monitor.record_scan("proj", _report([], score=0), data_dir=dd)
    points = monitor.trend("proj", data_dir=dd)
    assert len(points) == 2
    assert [p["score"] for p in points] == [70, 0]


def test_targets_are_isolated(tmp_path):
    dd = str(tmp_path)
    monitor.record_scan("proj-a", _report([_f("A")]), data_dir=dd)
    assert monitor.list_snapshots("proj-b", data_dir=dd) == []
