from pathlib import Path

from cloudnova.core.engine import Engine


def test_brute_force_aggregates_per_ip(tmp_path: Path):
    lines = "".join(
        "x sshd[1]: Failed password for invalid user admin from 10.0.0.5\n" for _ in range(120)
    )
    (tmp_path / "auth.log").write_text(lines, encoding="utf-8")
    findings = Engine().scan_path(tmp_path).findings
    # 120 lines -> exactly ONE finding, not 120 cards.
    assert len(findings) == 1
    assert "120 failed" in findings[0].evidence
    assert findings[0].severity.value == "high"


def test_single_failure_not_flagged(tmp_path: Path):
    (tmp_path / "auth.log").write_text(
        "x sshd[1]: Failed password for root from 1.2.3.4\n", encoding="utf-8"
    )
    assert not Engine().scan_path(tmp_path).findings
