"""Read-only boto3 collector for AWS. Isolated so the checks stay import-light.

Every call here is a Describe/Get/List - nothing is created, changed, or deleted.
Each service is wrapped in try/except so a credential with partial permissions
still yields a partial inventory instead of failing the whole scan.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from cloudnova.cloud.aws import (
    AwsInventory,
    IamUser,
    RdsInstance,
    S3Bucket,
    SecurityGroup,
)


def _age_days(when: Any) -> int | None:
    if not isinstance(when, datetime):
        return None
    return (datetime.now(UTC) - when).days


def collect(profile: str | None = None, region: str | None = None) -> AwsInventory:
    import boto3

    session = boto3.Session(profile_name=profile, region_name=region)
    inv = AwsInventory()

    try:
        inv.account = session.client("sts").get_caller_identity()["Account"]
    except Exception:
        inv.account = "unknown"

    _collect_s3(session, inv)
    _collect_iam(session, inv)
    _collect_ec2(session, inv)
    _collect_rds(session, inv)
    return inv


def _collect_s3(session: Any, inv: AwsInventory) -> None:
    try:
        s3 = session.client("s3")
        for b in s3.list_buckets().get("Buckets", []):
            name = b["Name"]
            bucket = S3Bucket(name=name)
            try:
                pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                bucket.public_access_block = all(pab.get(k, False) for k in pab)
            except Exception:
                bucket.public_access_block = False
            try:
                grants = s3.get_bucket_acl(Bucket=name).get("Grants", [])
                bucket.public_acl = any(
                    g.get("Grantee", {}).get("URI", "").endswith("AllUsers") for g in grants
                )
            except Exception:
                pass
            try:
                s3.get_bucket_encryption(Bucket=name)
                bucket.encrypted = True
            except Exception:
                bucket.encrypted = False
            inv.buckets.append(bucket)
    except Exception:
        pass


def _collect_iam(session: Any, inv: AwsInventory) -> None:
    try:
        iam = session.client("iam")
        for u in iam.list_users().get("Users", []):
            name = u["UserName"]
            user = IamUser(name=name)
            try:
                iam.get_login_profile(UserName=name)
                user.has_console_password = True
            except Exception:
                user.has_console_password = False
            try:
                user.mfa_enabled = bool(iam.list_mfa_devices(UserName=name).get("MFADevices"))
            except Exception:
                pass
            try:
                ages = [
                    _age_days(k.get("CreateDate"))
                    for k in iam.list_access_keys(UserName=name).get("AccessKeyMetadata", [])
                    if k.get("Status") == "Active"
                ]
                real = [a for a in ages if a is not None]
                user.active_key_age_days = max(real) if real else None
            except Exception:
                pass
            inv.iam_users.append(user)
    except Exception:
        pass


def _collect_ec2(session: Any, inv: AwsInventory) -> None:
    try:
        ec2 = session.client("ec2")
        for sg in ec2.describe_security_groups().get("SecurityGroups", []):
            group = SecurityGroup(id=sg["GroupId"], name=sg.get("GroupName", ""))
            for perm in sg.get("IpPermissions", []):
                from_port = int(perm.get("FromPort", 0) or 0)
                to_port = int(perm.get("ToPort", 65535) or 65535)
                for rng in perm.get("IpRanges", []):
                    group.world_ingress.append((from_port, to_port, rng.get("CidrIp", "")))
                for rng in perm.get("Ipv6Ranges", []):
                    group.world_ingress.append((from_port, to_port, rng.get("CidrIpv6", "")))
            inv.security_groups.append(group)
    except Exception:
        pass


def _collect_rds(session: Any, inv: AwsInventory) -> None:
    try:
        rds = session.client("rds")
        for db in rds.describe_db_instances().get("DBInstances", []):
            inv.rds.append(
                RdsInstance(
                    id=db.get("DBInstanceIdentifier", "?"),
                    public=bool(db.get("PubliclyAccessible", False)),
                    encrypted=bool(db.get("StorageEncrypted", False)),
                )
            )
    except Exception:
        pass
