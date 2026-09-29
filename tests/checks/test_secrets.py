"""Secret scanning: universal check over raw text, redacted evidence."""

from pathlib import Path

from cloudnova.core.engine import Engine


def _scan(tmp_path: Path, content: str, name="main.tf"):
    (tmp_path / name).write_text(content, encoding="utf-8")
    return Engine().scan_path(tmp_path).findings


def _secrets(findings):
    return [f for f in findings if f.check_id == "SECRET_HARDCODED"]


def test_aws_access_key_detected(tmp_path):
    s = _secrets(_scan(tmp_path, 'key = "AKIAIOSFODNN7EXAMPLE"\n'))
    assert len(s) == 1
    assert s[0].severity.value == "critical"
    assert s[0].location.line == 1


def test_evidence_is_redacted(tmp_path):
    s = _secrets(_scan(tmp_path, 'key = "AKIAIOSFODNN7EXAMPLE"\n'))
    # The raw secret must never appear in the report.
    assert "AKIAIOSFODNN7EXAMPLE" not in (s[0].evidence or "")
    assert "…" in (s[0].evidence or "")


def test_private_key_block_detected(tmp_path):
    s = _secrets(_scan(tmp_path, "-----BEGIN RSA PRIVATE KEY-----\nabc\n", name="k.yaml"))
    assert any("Private key" in f.title for f in s)


def test_runs_on_any_format(tmp_path):
    # Universal check: fires on a Kubernetes manifest too, not just IaC.
    manifest = (
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n"
        'data:\n  ghtoken: "ghp_' + "a" * 36 + '"\n'
    )
    s = _secrets(_scan(tmp_path, manifest, name="secret.yaml"))
    assert any("GitHub" in f.title for f in s)


def test_clean_file_no_secrets(tmp_path):
    s = _secrets(_scan(tmp_path, 'resource "aws_s3_bucket" "b" { bucket = "my-data" }\n'))
    assert s == []


def test_same_secret_reported_once_per_line(tmp_path):
    s = _secrets(_scan(tmp_path, 'a = "AKIAIOSFODNN7EXAMPLE"\nb = "AKIAIOSFODNN7EXAMPLE"\n'))
    assert len(s) == 2  # once per line, not deduped across lines
    assert {f.location.line for f in s} == {1, 2}
