"""Terraform rules for data at rest: encryption, backups, and exposure.

Grouped by what an attacker is after rather than by AWS service. Every rule
here is about a store of data being readable, unrecoverable, or reachable when
it should not be. Mapped to CIS AWS Benchmark controls and MITRE ATT&CK.
"""

from __future__ import annotations

from collections.abc import Iterator

from cloudnova.checks._tf_base import AttributeCheck, TerraformCheck, first, missing, truthy
from cloudnova.core.check import register
from cloudnova.core.findings import Confidence, Finding, Severity
from cloudnova.core.resource import CloudResource


@register
class RdsNoEncryption(AttributeCheck):
    id = "TF_RDS_NO_ENCRYPTION"
    title = "RDS instance is not encrypted at rest"
    severity = Severity.HIGH
    types = frozenset({"aws_db_instance", "aws_rds_cluster"})
    attribute = "storage_encrypted"
    description_template = (
        "Database '{name}' stores data unencrypted. A snapshot copy, a stolen "
        "volume, or an over-permissive snapshot share exposes it in full."
    )
    remediation_text = "Set storage_encrypted = true and supply a kms_key_id."
    cis = ("CIS AWS 2.3.1",)
    mitre = ("T1530",)


@register
class RdsNoBackups(TerraformCheck):
    id = "TF_RDS_NO_BACKUPS"
    title = "RDS instance has backups disabled"
    severity = Severity.MEDIUM

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "aws_db_instance":
            return
        raw = first(resource.get("backup_retention_period"))
        try:
            days = int(raw) if raw is not None else 0
        except (TypeError, ValueError):
            return
        if days > 0:
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Database '{resource.name}' has backup_retention_period = {days}, so "
                "there is no point-in-time recovery. Ransomware and accidental "
                "deletion are both unrecoverable."
            ),
            remediation="Set backup_retention_period to at least 7 days.",
            evidence=f"backup_retention_period = {days}",
            cis_controls=["CIS AWS 2.3.2"],
            mitre_attack=["T1485"],
        )


@register
class RdsNoDeletionProtection(AttributeCheck):
    id = "TF_RDS_NO_DELETION_PROTECTION"
    title = "RDS instance has no deletion protection"
    severity = Severity.LOW
    types = frozenset({"aws_db_instance", "aws_rds_cluster"})
    attribute = "deletion_protection"
    description_template = (
        "Database '{name}' can be destroyed by a single API call or a careless terraform apply."
    )
    remediation_text = "Set deletion_protection = true on production databases."
    cis = ()
    mitre = ("T1485",)


@register
class DynamoNoEncryption(TerraformCheck):
    id = "TF_DYNAMODB_NO_ENCRYPTION"
    title = "DynamoDB table does not use a customer-managed key"
    severity = Severity.LOW

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "aws_dynamodb_table":
            return
        block = first(resource.get("server_side_encryption"))
        if isinstance(block, dict) and truthy(block.get("enabled")):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.MEDIUM,
            location=self.loc(resource),
            description=(
                f"Table '{resource.name}' relies on the AWS-owned default key. That "
                "is encrypted, but you cannot audit, rotate, or revoke the key, so "
                "key access cannot be separated from table access."
            ),
            remediation=(
                "Add a server_side_encryption block with enabled = true and a "
                "kms_key_arn you control."
            ),
            evidence="server_side_encryption absent or disabled",
            cis_controls=[],
            mitre_attack=["T1530"],
        )


@register
class DynamoNoPitr(TerraformCheck):
    id = "TF_DYNAMODB_NO_PITR"
    title = "DynamoDB table has no point-in-time recovery"
    severity = Severity.MEDIUM

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "aws_dynamodb_table":
            return
        block = first(resource.get("point_in_time_recovery"))
        if isinstance(block, dict) and truthy(block.get("enabled")):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Table '{resource.name}' cannot be restored to a point in time. A "
                "destructive write or a ransomware event is permanent."
            ),
            remediation="Add point_in_time_recovery { enabled = true }.",
            evidence="point_in_time_recovery absent or disabled",
            cis_controls=[],
            mitre_attack=["T1485"],
        )


@register
class EfsNoEncryption(AttributeCheck):
    id = "TF_EFS_NO_ENCRYPTION"
    title = "EFS file system is not encrypted at rest"
    severity = Severity.HIGH
    types = frozenset({"aws_efs_file_system"})
    attribute = "encrypted"
    description_template = "File system '{name}' stores data unencrypted on shared storage."
    remediation_text = "Set encrypted = true and supply a kms_key_id."
    cis = ()
    mitre = ("T1530",)


@register
class RedshiftPublic(AttributeCheck):
    id = "TF_REDSHIFT_PUBLIC"
    title = "Redshift cluster is publicly accessible"
    severity = Severity.CRITICAL
    types = frozenset({"aws_redshift_cluster"})
    attribute = "publicly_accessible"
    invert = True
    description_template = (
        "Data warehouse '{name}' has a public endpoint. Redshift clusters hold "
        "aggregated business data, which makes one credential worth an entire "
        "estate."
    )
    remediation_text = (
        "Set publicly_accessible = false and reach it through a VPC endpoint or a bastion."
    )
    cis = ()
    mitre = ("T1530",)


@register
class RedshiftNoEncryption(AttributeCheck):
    id = "TF_REDSHIFT_NO_ENCRYPTION"
    title = "Redshift cluster is not encrypted at rest"
    severity = Severity.HIGH
    types = frozenset({"aws_redshift_cluster"})
    attribute = "encrypted"
    description_template = "Data warehouse '{name}' stores data unencrypted."
    remediation_text = "Set encrypted = true with a kms_key_id."
    cis = ()
    mitre = ("T1530",)


@register
class SqsNoEncryption(TerraformCheck):
    id = "TF_SQS_NO_ENCRYPTION"
    title = "SQS queue is not encrypted at rest"
    severity = Severity.MEDIUM

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "aws_sqs_queue":
            return
        if not missing(resource.get("kms_master_key_id")) or truthy(
            resource.get("sqs_managed_sse_enabled")
        ):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Queue '{resource.name}' is unencrypted. Message bodies routinely "
                "carry identifiers, tokens and personal data in transit between "
                "services."
            ),
            remediation=(
                "Set sqs_managed_sse_enabled = true, or supply kms_master_key_id for "
                "a key you control."
            ),
            evidence="no kms_master_key_id and sqs_managed_sse_enabled not set",
            cis_controls=[],
            mitre_attack=["T1530"],
        )


@register
class SnsNoEncryption(AttributeCheck):
    id = "TF_SNS_NO_ENCRYPTION"
    title = "SNS topic is not encrypted at rest"
    severity = Severity.MEDIUM
    types = frozenset({"aws_sns_topic"})
    attribute = "kms_master_key_id"
    description_template = "Topic '{name}' is unencrypted, so queued notifications are readable."
    remediation_text = "Set kms_master_key_id to a KMS key."
    cis = ()
    mitre = ("T1530",)


@register
class S3NoVersioning(TerraformCheck):
    id = "TF_S3_NO_VERSIONING"
    title = "S3 bucket has versioning disabled"
    severity = Severity.MEDIUM

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type == "aws_s3_bucket_versioning":
            block = first(resource.get("versioning_configuration"))
            if (
                isinstance(block, dict)
                and str(first(block.get("status")) or "").lower() == "enabled"
            ):
                return
        elif resource.type == "aws_s3_bucket":
            block = first(resource.get("versioning"))
            if isinstance(block, dict) and truthy(block.get("enabled")):
                return
        else:
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.MEDIUM,
            location=self.loc(resource),
            description=(
                f"Bucket '{resource.name}' has no versioning, so an overwrite or "
                "delete is final. This is the control that makes S3 ransomware "
                "survivable."
            ),
            remediation=(
                "Enable versioning, and add MFA delete or a lifecycle policy for retention."
            ),
            evidence="versioning not enabled",
            cis_controls=["CIS AWS 2.1.3"],
            mitre_attack=["T1485", "T1490"],
        )


@register
class S3NoPublicAccessBlock(TerraformCheck):
    id = "TF_S3_NO_PUBLIC_ACCESS_BLOCK"
    title = "S3 public access block is incomplete"
    severity = Severity.HIGH

    _FLAGS = (
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets",
    )

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "aws_s3_bucket_public_access_block":
            return
        off = [flag for flag in self._FLAGS if not truthy(resource.get(flag))]
        if not off:
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Public access block on '{resource.name}' leaves {', '.join(off)} "
                "unset. A later ACL or bucket policy change can then make objects "
                "public with nothing to stop it."
            ),
            remediation=f"Set {', '.join(off)} to true.",
            evidence=f"unset: {', '.join(off)}",
            cis_controls=["CIS AWS 2.1.5"],
            mitre_attack=["T1530"],
        )


@register
class SecretNoRotation(TerraformCheck):
    id = "TF_SECRET_NO_ROTATION"
    title = "Secrets Manager secret has no automatic rotation"
    severity = Severity.LOW

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "aws_secretsmanager_secret":
            return
        if not missing(resource.get("rotation_rules")):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.MEDIUM,
            location=self.loc(resource),
            description=(
                f"Secret '{resource.name}' never rotates, so a leaked value stays "
                "valid indefinitely and the blast radius of any past exposure never "
                "shrinks."
            ),
            remediation=(
                "Attach a rotation lambda and a rotation_rules block with an interval "
                "of 90 days or less."
            ),
            evidence="rotation_rules absent",
            cis_controls=[],
            mitre_attack=["T1552"],
        )
