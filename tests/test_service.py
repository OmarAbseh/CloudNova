"""The programmatic API returns plain, correct dicts for non-CLI callers."""

import pytest

from cloudnova import service


def _tf(tmp_path, body='resource "aws_s3_bucket" "b" { acl = "public-read" }\n'):
    (tmp_path / "main.tf").write_text(body, encoding="utf-8")
    return str(tmp_path)


def test_scan_returns_summary_and_findings(tmp_path):
    out = service.scan(_tf(tmp_path))
    assert out["summary"]["findings"] >= 1
    assert set(out["summary"]["severity_counts"]) == {
        "critical",
        "high",
        "medium",
        "low",
        "info",
    }
    assert all("check_id" in f for f in out["findings"])


def test_scan_missing_path_raises():
    with pytest.raises(FileNotFoundError):
        service.scan("/no/such/path")


def test_scan_min_severity_filters(tmp_path):
    body = "access_control:\n  public: true\nsession:\n  timeout: 0\n"
    (tmp_path / "c.yaml").write_text(body, encoding="utf-8")
    out = service.scan(str(tmp_path), min_severity="high")
    ids = {f["check_id"] for f in out["findings"]}
    assert "IAC_ACCESS_PUBLIC" in ids
    assert "IAC_SESSION_NO_TIMEOUT" not in ids


def test_list_checks():
    out = service.list_checks()
    assert out["count"] == len(out["checks"]) > 0
    assert any(c["id"] == "TF_S3_PUBLIC_ACL" for c in out["checks"])


def test_attack_paths(tmp_path):
    chain = """
resource "aws_security_group" "web" {
  ingress { from_port = 22
    to_port = 22
    cidr_blocks = ["0.0.0.0/0"] }
}
resource "aws_instance" "web" {
  vpc_security_group_ids = [aws_security_group.web.id]
  iam_instance_profile   = aws_iam_instance_profile.app.name
}
resource "aws_iam_instance_profile" "app" { role = aws_iam_role.app.name }
resource "aws_iam_role" "app" { name = "app" }
resource "aws_iam_role_policy" "admin" {
  role   = aws_iam_role.app.id
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
}
"""
    out = service.attack_paths(_tf(tmp_path, chain))
    assert out["count"] == 1
    assert out["paths"][0]["entry"] == "aws_instance.web"
