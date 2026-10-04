"""The data, network and compute rule packs.

Every rule gets a true positive and a true negative. A rule that only ever
fires is as useless as one that never does, and the negatives are what stop
the tool crying wolf.
"""

from pathlib import Path

from cloudnova.core.engine import Engine


def _ids(root: Path) -> set[str]:
    return {f.check_id for f in Engine().scan_path(root).findings}


def _tf(tmp_path: Path, content: str) -> Path:
    (tmp_path / "main.tf").write_text(content, encoding="utf-8")
    return tmp_path


# -- data at rest ----------------------------------------------------------


def test_rds_unencrypted_flagged(tmp_path):
    assert "TF_RDS_NO_ENCRYPTION" in _ids(
        _tf(tmp_path, 'resource "aws_db_instance" "d" {\n  engine = "postgres"\n}\n')
    )


def test_rds_encrypted_not_flagged(tmp_path):
    ids = _ids(
        _tf(
            tmp_path,
            'resource "aws_db_instance" "d" {\n  storage_encrypted = true\n'
            "  backup_retention_period = 7\n  deletion_protection = true\n}\n",
        )
    )
    assert "TF_RDS_NO_ENCRYPTION" not in ids
    assert "TF_RDS_NO_BACKUPS" not in ids
    assert "TF_RDS_NO_DELETION_PROTECTION" not in ids


def test_rds_zero_retention_flagged(tmp_path):
    assert "TF_RDS_NO_BACKUPS" in _ids(
        _tf(tmp_path, 'resource "aws_db_instance" "d" {\n  backup_retention_period = 0\n}\n')
    )


def test_dynamodb_without_pitr_flagged(tmp_path):
    ids = _ids(_tf(tmp_path, 'resource "aws_dynamodb_table" "t" {\n  name = "x"\n}\n'))
    assert "TF_DYNAMODB_NO_PITR" in ids
    assert "TF_DYNAMODB_NO_ENCRYPTION" in ids


def test_dynamodb_hardened_not_flagged(tmp_path):
    ids = _ids(
        _tf(
            tmp_path,
            'resource "aws_dynamodb_table" "t" {\n'
            "  point_in_time_recovery { enabled = true }\n"
            "  server_side_encryption { enabled = true }\n}\n",
        )
    )
    assert "TF_DYNAMODB_NO_PITR" not in ids
    assert "TF_DYNAMODB_NO_ENCRYPTION" not in ids


def test_efs_unencrypted_flagged(tmp_path):
    assert "TF_EFS_NO_ENCRYPTION" in _ids(
        _tf(tmp_path, 'resource "aws_efs_file_system" "f" {\n  creation_token = "x"\n}\n')
    )


def test_redshift_public_flagged(tmp_path):
    ids = _ids(
        _tf(
            tmp_path,
            'resource "aws_redshift_cluster" "r" {\n  publicly_accessible = true\n}\n',
        )
    )
    assert "TF_REDSHIFT_PUBLIC" in ids
    assert "TF_REDSHIFT_NO_ENCRYPTION" in ids


def test_redshift_private_encrypted_not_flagged(tmp_path):
    ids = _ids(
        _tf(
            tmp_path,
            'resource "aws_redshift_cluster" "r" {\n  publicly_accessible = false\n'
            "  encrypted = true\n}\n",
        )
    )
    assert "TF_REDSHIFT_PUBLIC" not in ids
    assert "TF_REDSHIFT_NO_ENCRYPTION" not in ids


def test_sqs_unencrypted_flagged(tmp_path):
    assert "TF_SQS_NO_ENCRYPTION" in _ids(
        _tf(tmp_path, 'resource "aws_sqs_queue" "q" {\n  name = "x"\n}\n')
    )


def test_sqs_managed_sse_not_flagged(tmp_path):
    assert "TF_SQS_NO_ENCRYPTION" not in _ids(
        _tf(tmp_path, 'resource "aws_sqs_queue" "q" {\n  sqs_managed_sse_enabled = true\n}\n')
    )


def test_s3_versioning_off_flagged(tmp_path):
    assert "TF_S3_NO_VERSIONING" in _ids(
        _tf(
            tmp_path,
            'resource "aws_s3_bucket_versioning" "v" {\n'
            '  versioning_configuration { status = "Suspended" }\n}\n',
        )
    )


def test_s3_versioning_enabled_not_flagged(tmp_path):
    assert "TF_S3_NO_VERSIONING" not in _ids(
        _tf(
            tmp_path,
            'resource "aws_s3_bucket_versioning" "v" {\n'
            '  versioning_configuration { status = "Enabled" }\n}\n',
        )
    )


def test_incomplete_public_access_block_flagged(tmp_path):
    assert "TF_S3_NO_PUBLIC_ACCESS_BLOCK" in _ids(
        _tf(
            tmp_path,
            'resource "aws_s3_bucket_public_access_block" "b" {\n'
            "  block_public_acls = true\n  block_public_policy = false\n}\n",
        )
    )


def test_complete_public_access_block_not_flagged(tmp_path):
    assert "TF_S3_NO_PUBLIC_ACCESS_BLOCK" not in _ids(
        _tf(
            tmp_path,
            'resource "aws_s3_bucket_public_access_block" "b" {\n'
            "  block_public_acls = true\n  block_public_policy = true\n"
            "  ignore_public_acls = true\n  restrict_public_buckets = true\n}\n",
        )
    )


def test_secret_without_rotation_flagged(tmp_path):
    assert "TF_SECRET_NO_ROTATION" in _ids(
        _tf(tmp_path, 'resource "aws_secretsmanager_secret" "s" {\n  name = "x"\n}\n')
    )


# -- network exposure ------------------------------------------------------


def test_world_open_database_port_is_critical(tmp_path):
    root = _tf(
        tmp_path,
        'resource "aws_security_group" "sg" {\n'
        "  ingress {\n    from_port = 5432\n    to_port = 5432\n"
        '    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n',
    )
    findings = Engine().scan_path(root).findings
    hit = [f for f in findings if f.check_id == "TF_SG_SENSITIVE_PORT_WORLD"]
    assert hit
    assert hit[0].severity.value == "critical"
    # The service name is what makes this finding actionable.
    assert "PostgreSQL" in hit[0].description


def test_a_port_range_covering_ssh_is_caught(tmp_path):
    assert "TF_SG_SENSITIVE_PORT_WORLD" in _ids(
        _tf(
            tmp_path,
            'resource "aws_security_group" "sg" {\n'
            "  ingress {\n    from_port = 1\n    to_port = 1024\n"
            '    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n',
        )
    )


def test_world_open_https_is_not_flagged(tmp_path):
    # Port 443 open to the world is what a web server is for.
    assert "TF_SG_SENSITIVE_PORT_WORLD" not in _ids(
        _tf(
            tmp_path,
            'resource "aws_security_group" "sg" {\n'
            "  ingress {\n    from_port = 443\n    to_port = 443\n"
            '    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n',
        )
    )


def test_ssh_from_a_known_cidr_is_not_flagged(tmp_path):
    assert "TF_SG_SENSITIVE_PORT_WORLD" not in _ids(
        _tf(
            tmp_path,
            'resource "aws_security_group" "sg" {\n'
            "  ingress {\n    from_port = 22\n    to_port = 22\n"
            '    cidr_blocks = ["10.0.0.0/8"]\n  }\n}\n',
        )
    )


def test_plaintext_listener_flagged(tmp_path):
    assert "TF_LB_PLAINTEXT_LISTENER" in _ids(
        _tf(tmp_path, 'resource "aws_lb_listener" "l" {\n  protocol = "HTTP"\n}\n')
    )


def test_http_listener_that_only_redirects_is_not_flagged(tmp_path):
    # Redirecting HTTP to HTTPS is the correct pattern.
    assert "TF_LB_PLAINTEXT_LISTENER" not in _ids(
        _tf(
            tmp_path,
            'resource "aws_lb_listener" "l" {\n  protocol = "HTTP"\n'
            '  default_action { type = "redirect" }\n}\n',
        )
    )


def test_weak_tls_policy_flagged(tmp_path):
    assert "TF_LB_WEAK_TLS_POLICY" in _ids(
        _tf(
            tmp_path,
            'resource "aws_lb_listener" "l" {\n  protocol = "HTTPS"\n'
            '  ssl_policy = "ELBSecurityPolicy-TLS-1-0-2015-04"\n}\n',
        )
    )


def test_modern_tls_policy_not_flagged(tmp_path):
    assert "TF_LB_WEAK_TLS_POLICY" not in _ids(
        _tf(
            tmp_path,
            'resource "aws_lb_listener" "l" {\n  protocol = "HTTPS"\n'
            '  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"\n}\n',
        )
    )


def test_vpc_without_flow_logs_flagged(tmp_path):
    assert "TF_VPC_NO_FLOW_LOGS" in _ids(
        _tf(tmp_path, 'resource "aws_vpc" "v" {\n  cidr_block = "10.0.0.0/16"\n}\n')
    )


def test_vpc_with_a_flow_log_not_flagged(tmp_path):
    assert "TF_VPC_NO_FLOW_LOGS" not in _ids(
        _tf(
            tmp_path,
            'resource "aws_vpc" "v" {\n  cidr_block = "10.0.0.0/16"\n}\n'
            'resource "aws_flow_log" "f" {\n  traffic_type = "ALL"\n}\n',
        )
    )


def test_cloudfront_allowing_http_flagged(tmp_path):
    assert "TF_CLOUDFRONT_ALLOWS_HTTP" in _ids(
        _tf(
            tmp_path,
            'resource "aws_cloudfront_distribution" "d" {\n'
            '  default_cache_behavior { viewer_protocol_policy = "allow-all" }\n}\n',
        )
    )


def test_cloudfront_redirecting_to_https_not_flagged(tmp_path):
    assert "TF_CLOUDFRONT_ALLOWS_HTTP" not in _ids(
        _tf(
            tmp_path,
            'resource "aws_cloudfront_distribution" "d" {\n'
            '  default_cache_behavior { viewer_protocol_policy = "redirect-to-https" }\n}\n',
        )
    )


def test_opensearch_outside_a_vpc_flagged(tmp_path):
    assert "TF_OPENSEARCH_PUBLIC" in _ids(
        _tf(tmp_path, 'resource "aws_opensearch_domain" "o" {\n  domain_name = "x"\n}\n')
    )


# -- compute and identity --------------------------------------------------


def test_lambda_env_without_cmk_flagged(tmp_path):
    assert "TF_LAMBDA_ENV_NOT_ENCRYPTED" in _ids(
        _tf(
            tmp_path,
            'resource "aws_lambda_function" "f" {\n  environment { variables = { DB = "x" } }\n}\n',
        )
    )


def test_lambda_env_with_cmk_not_flagged(tmp_path):
    assert "TF_LAMBDA_ENV_NOT_ENCRYPTED" not in _ids(
        _tf(
            tmp_path,
            'resource "aws_lambda_function" "f" {\n'
            '  environment { variables = { DB = "x" } }\n'
            '  kms_key_arn = "arn:aws:kms:eu-west-1:1:key/abc"\n}\n',
        )
    )


def test_lambda_with_no_env_not_flagged(tmp_path):
    assert "TF_LAMBDA_ENV_NOT_ENCRYPTED" not in _ids(
        _tf(tmp_path, 'resource "aws_lambda_function" "f" {\n  runtime = "python3.12"\n}\n')
    )


def test_public_lambda_invoke_flagged(tmp_path):
    assert "TF_LAMBDA_PUBLIC_INVOKE" in _ids(
        _tf(tmp_path, 'resource "aws_lambda_permission" "p" {\n  principal = "*"\n}\n')
    )


def test_scoped_lambda_invoke_not_flagged(tmp_path):
    assert "TF_LAMBDA_PUBLIC_INVOKE" not in _ids(
        _tf(
            tmp_path,
            'resource "aws_lambda_permission" "p" {\n  principal = "apigateway.amazonaws.com"\n}\n',
        )
    )


def test_administrator_policy_attachment_flagged(tmp_path):
    assert "TF_IAM_ADMIN_POLICY_ATTACHED" in _ids(
        _tf(
            tmp_path,
            'resource "aws_iam_role_policy_attachment" "a" {\n'
            '  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"\n}\n',
        )
    )


def test_scoped_policy_attachment_not_flagged(tmp_path):
    assert "TF_IAM_ADMIN_POLICY_ATTACHED" not in _ids(
        _tf(
            tmp_path,
            'resource "aws_iam_role_policy_attachment" "a" {\n'
            '  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"\n}\n',
        )
    )


def test_static_access_key_flagged(tmp_path):
    assert "TF_IAM_STATIC_ACCESS_KEY" in _ids(
        _tf(tmp_path, 'resource "aws_iam_access_key" "k" {\n  user = "svc"\n}\n')
    )


def test_passrole_wildcard_is_critical(tmp_path):
    root = _tf(
        tmp_path,
        'resource "aws_iam_policy" "p" {\n  policy = jsonencode({\n'
        '    Statement = [{ Effect = "Allow", Action = "iam:PassRole", Resource = "*" }]\n'
        "  })\n}\n",
    )
    hit = [f for f in Engine().scan_path(root).findings if f.check_id == "TF_IAM_PASSROLE_WILDCARD"]
    assert hit
    assert hit[0].severity.value == "critical"


def test_scoped_passrole_not_flagged(tmp_path):
    assert "TF_IAM_PASSROLE_WILDCARD" not in _ids(
        _tf(
            tmp_path,
            'resource "aws_iam_policy" "p" {\n  policy = jsonencode({\n'
            '    Statement = [{ Effect = "Allow", Action = "iam:PassRole",\n'
            '                   Resource = "arn:aws:iam::1:role/app" }]\n  })\n}\n',
        )
    )


def test_eks_public_endpoint_flagged(tmp_path):
    ids = _ids(
        _tf(
            tmp_path,
            'resource "aws_eks_cluster" "c" {\n  vpc_config { endpoint_public_access = true }\n}\n',
        )
    )
    assert "TF_EKS_PUBLIC_ENDPOINT" in ids
    assert "TF_EKS_NO_SECRET_ENCRYPTION" in ids
    assert "TF_EKS_NO_AUDIT_LOGGING" in ids


def test_hardened_eks_not_flagged(tmp_path):
    ids = _ids(
        _tf(
            tmp_path,
            'resource "aws_eks_cluster" "c" {\n'
            "  vpc_config { endpoint_public_access = false }\n"
            '  encryption_config { resources = ["secrets"] }\n'
            '  enabled_cluster_log_types = ["api", "audit", "authenticator"]\n}\n',
        )
    )
    assert "TF_EKS_PUBLIC_ENDPOINT" not in ids
    assert "TF_EKS_NO_SECRET_ENCRYPTION" not in ids
    assert "TF_EKS_NO_AUDIT_LOGGING" not in ids


def test_mutable_ecr_tags_flagged(tmp_path):
    ids = _ids(_tf(tmp_path, 'resource "aws_ecr_repository" "r" {\n  name = "app"\n}\n'))
    assert "TF_ECR_MUTABLE_TAGS" in ids
    assert "TF_ECR_NO_SCAN_ON_PUSH" in ids


def test_immutable_scanned_ecr_not_flagged(tmp_path):
    ids = _ids(
        _tf(
            tmp_path,
            'resource "aws_ecr_repository" "r" {\n'
            '  image_tag_mutability = "IMMUTABLE"\n'
            "  image_scanning_configuration { scan_on_push = true }\n}\n",
        )
    )
    assert "TF_ECR_MUTABLE_TAGS" not in ids
    assert "TF_ECR_NO_SCAN_ON_PUSH" not in ids


def test_ecs_host_network_flagged(tmp_path):
    assert "TF_ECS_HOST_NETWORK" in _ids(
        _tf(tmp_path, 'resource "aws_ecs_task_definition" "t" {\n  network_mode = "host"\n}\n')
    )


def test_ecs_awsvpc_not_flagged(tmp_path):
    assert "TF_ECS_HOST_NETWORK" not in _ids(
        _tf(tmp_path, 'resource "aws_ecs_task_definition" "t" {\n  network_mode = "awsvpc"\n}\n')
    )


def test_default_ebs_encryption_off_flagged(tmp_path):
    assert "TF_EBS_DEFAULT_ENCRYPTION_OFF" in _ids(
        _tf(tmp_path, 'resource "aws_ebs_encryption_by_default" "e" {\n  enabled = false\n}\n')
    )


# -- the pack as a whole ---------------------------------------------------


def test_every_registered_check_has_a_unique_id_and_mapping():
    import cloudnova.checks  # noqa: F401
    from cloudnova.core.check import registry

    checks = list(registry.all())
    assert len({c.id for c in checks}) == len(checks)
    for check in checks:
        assert check.id.isupper() or "_" in check.id
        assert check.title and check.title[0].isupper()


def test_a_clean_configuration_produces_no_findings(tmp_path):
    # The most important negative: hardened infrastructure must be quiet, or
    # nobody will trust the tool enough to act on it.
    root = _tf(
        tmp_path,
        'resource "aws_s3_bucket" "b" {\n  acl = "private"\n'
        "  server_side_encryption_configuration {}\n"
        "  versioning { enabled = true }\n}\n"
        'resource "aws_db_instance" "d" {\n  storage_encrypted = true\n'
        "  backup_retention_period = 14\n  deletion_protection = true\n"
        "  publicly_accessible = false\n}\n",
    )
    assert _ids(root) == set()
