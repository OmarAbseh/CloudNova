"""AWS live-scan checks: findings fire on bad config, quiet on good (pure, no boto3)."""

from cloudnova.cloud.aws import (
    AwsInventory,
    IamUser,
    RdsInstance,
    S3Bucket,
    SecurityGroup,
    analyze_aws,
    scan_aws,
)
from cloudnova.core.findings import Severity


def _ids(findings):
    return {f.check_id for f in findings}


def test_public_bucket_flagged():
    inv = AwsInventory(buckets=[S3Bucket("data", public_access_block=False, public_acl=True)])
    findings = analyze_aws(inv)
    assert "AWS_S3_PUBLIC" in _ids(findings)
    assert findings[0].severity is Severity.CRITICAL  # public ACL is critical, sorted first


def test_hardened_bucket_clean():
    inv = AwsInventory(
        buckets=[S3Bucket("data", public_access_block=True, public_acl=False, encrypted=True)]
    )
    assert analyze_aws(inv) == []


def test_iam_no_mfa_and_stale_key():
    inv = AwsInventory(
        iam_users=[
            IamUser("bob", has_console_password=True, mfa_enabled=False, active_key_age_days=200)
        ]
    )
    ids = _ids(analyze_aws(inv))
    assert "AWS_IAM_NO_MFA" in ids
    assert "AWS_IAM_STALE_KEY" in ids


def test_iam_clean_user():
    inv = AwsInventory(
        iam_users=[
            IamUser("svc", has_console_password=False, mfa_enabled=True, active_key_age_days=10)
        ]
    )
    assert analyze_aws(inv) == []


def test_world_open_ssh_is_critical():
    inv = AwsInventory(
        security_groups=[SecurityGroup("sg-1", "web", world_ingress=[(22, 22, "0.0.0.0/0")])]
    )
    findings = analyze_aws(inv)
    assert findings and findings[0].check_id == "AWS_SG_WORLD_INGRESS"
    assert findings[0].severity is Severity.CRITICAL


def test_internal_sg_not_flagged():
    inv = AwsInventory(
        security_groups=[SecurityGroup("sg-2", "int", world_ingress=[(22, 22, "10.0.0.0/8")])]
    )
    assert analyze_aws(inv) == []


def test_rds_public_and_unencrypted():
    inv = AwsInventory(rds=[RdsInstance("db1", public=True, encrypted=False)])
    ids = _ids(analyze_aws(inv))
    assert {"AWS_RDS_PUBLIC", "AWS_RDS_NO_ENCRYPTION"} <= ids


def test_scan_aws_accepts_injected_inventory():
    # scan_aws must not touch boto3 when an inventory is supplied.
    inv = AwsInventory(buckets=[S3Bucket("x", public_acl=True)])
    assert _ids(scan_aws(inventory=inv)) == {"AWS_S3_PUBLIC"}
