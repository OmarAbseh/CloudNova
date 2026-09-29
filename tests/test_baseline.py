"""Baseline: accepted findings are suppressed; new ones still surface."""

from pathlib import Path

from cloudnova.core.baseline import Baseline, fingerprint
from cloudnova.core.engine import Engine


def _scan(root: Path):
    return Engine().scan_path(root)


def test_fingerprint_is_stable(tmp_path):
    (tmp_path / "c.yaml").write_text("access_control:\n  public: true\n", encoding="utf-8")
    f1 = _scan(tmp_path).findings[0]
    f2 = _scan(tmp_path).findings[0]
    assert fingerprint(f1) == fingerprint(f2)


def test_baseline_suppresses_known_findings(tmp_path):
    (tmp_path / "c.yaml").write_text("access_control:\n  public: true\n", encoding="utf-8")
    result = _scan(tmp_path)
    assert result.findings
    filtered = Baseline.from_result(result).filter(result)
    assert filtered.findings == []
    # Operational metadata is preserved through filtering.
    assert filtered.files_scanned == result.files_scanned


def test_new_finding_not_suppressed(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("access_control:\n  public: true\n", encoding="utf-8")
    baseline = Baseline.from_result(_scan(tmp_path))

    # Introduce a second, different issue.
    cfg.write_text(
        "access_control:\n  public: true\nauthentication:\n  password_required: false\n",
        encoding="utf-8",
    )
    filtered = baseline.filter(_scan(tmp_path))
    ids = {f.check_id for f in filtered.findings}
    assert ids == {"IAC_AUTH_NO_PASSWORD"}  # the new one survives, the old one is gone


def test_baseline_roundtrip(tmp_path):
    (tmp_path / "c.yaml").write_text("access_control:\n  public: true\n", encoding="utf-8")
    bl = Baseline.from_result(_scan(tmp_path))
    out = tmp_path / "bl.json"
    bl.save(out)
    reloaded = Baseline.load(out)
    assert reloaded.fingerprints == bl.fingerprints
