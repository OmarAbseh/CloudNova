"""Terraform check pack: each rule needs a true-positive and a true-negative."""

from pathlib import Path

from cloudnova.core.engine import Engine


def _ids(root: Path) -> set[str]:
    return {f.check_id for f in Engine().scan_path(root).findings}


def _write(tmp_path: Path, content: str) -> Path:
    (tmp_path / "main.tf").write_text(content, encoding="utf-8")
    return tmp_path


def test_s3_public_acl_flagged(tmp_path):
    root = _write(tmp_path, 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n')
    assert "TF_S3_PUBLIC_ACL" in _ids(root)


def test_s3_private_acl_not_flagged(tmp_path):
    root = _write(
        tmp_path,
        'resource "aws_s3_bucket" "b" {\n  acl = "private"\n'
        "  server_side_encryption_configuration {}\n}\n",
    )
    assert "TF_S3_PUBLIC_ACL" not in _ids(root)


def test_s3_missing_encryption_flagged(tmp_path):
    root = _write(tmp_path, 'resource "aws_s3_bucket" "b" {\n  acl = "private"\n}\n')
    assert "TF_S3_NO_ENCRYPTION" in _ids(root)


def test_s3_with_encryption_not_flagged(tmp_path):
    root = _write(
        tmp_path,
        'resource "aws_s3_bucket" "b" {\n  acl = "private"\n'
        "  server_side_encryption_configuration {\n    rule {}\n  }\n}\n",
    )
    assert "TF_S3_NO_ENCRYPTION" not in _ids(root)


def test_sg_world_ingress_on_ssh_is_critical(tmp_path):
    root = _write(
        tmp_path,
        'resource "aws_security_group" "sg" {\n'
        "  ingress {\n    from_port = 22\n    to_port = 22\n"
        '    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n',
    )
    findings = Engine().scan_path(root).findings
    sg = [f for f in findings if f.check_id == "TF_SG_WORLD_INGRESS"]
    assert sg and sg[0].severity.value == "critical"


def test_sg_restricted_cidr_not_flagged(tmp_path):
    root = _write(
        tmp_path,
        'resource "aws_security_group" "sg" {\n'
        "  ingress {\n    from_port = 22\n    to_port = 22\n"
        '    cidr_blocks = ["10.0.0.0/8"]\n  }\n}\n',
    )
    assert "TF_SG_WORLD_INGRESS" not in _ids(root)


def test_iam_wildcard_via_jsonencode_flagged(tmp_path):
    root = _write(
        tmp_path,
        'resource "aws_iam_role_policy" "p" {\n'
        "  policy = jsonencode({\n"
        '    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]\n'
        "  })\n}\n",
    )
    findings = Engine().scan_path(root).findings
    iam = [f for f in findings if f.check_id == "TF_IAM_WILDCARD"]
    assert iam and iam[0].severity.value == "critical"


def test_iam_scoped_policy_not_flagged(tmp_path):
    root = _write(
        tmp_path,
        'resource "aws_iam_role_policy" "p" {\n'
        "  policy = jsonencode({\n"
        '    Statement = [{ Effect = "Allow", Action = "s3:GetObject",\n'
        '                   Resource = "arn:aws:s3:::b/*" }]\n'
        "  })\n}\n",
    )
    assert "TF_IAM_WILDCARD" not in _ids(root)


def test_malformed_terraform_is_recorded_not_crashed(tmp_path):
    root = _write(tmp_path, 'resource "aws_s3_bucket" "b" {\n  acl = \n')  # syntax error
    result = Engine().scan_path(root)
    assert isinstance(result.findings, list)  # no exception


def test_rds_public_flagged(tmp_path):
    root = _write(tmp_path, 'resource "aws_db_instance" "db" {\n  publicly_accessible = true\n}\n')
    assert "TF_RDS_PUBLIC" in _ids(root)


def test_rds_private_not_flagged(tmp_path):
    root = _write(tmp_path, 'resource "aws_db_instance" "db" {\n  publicly_accessible = false\n}\n')
    assert "TF_RDS_PUBLIC" not in _ids(root)


def test_ebs_unencrypted_flagged(tmp_path):
    root = _write(tmp_path, 'resource "aws_ebs_volume" "v" {\n  size = 10\n}\n')
    assert "TF_EBS_NO_ENCRYPTION" in _ids(root)


def test_ebs_encrypted_not_flagged(tmp_path):
    root = _write(tmp_path, 'resource "aws_ebs_volume" "v" {\n  size = 10\n  encrypted = true\n}\n')
    assert "TF_EBS_NO_ENCRYPTION" not in _ids(root)
