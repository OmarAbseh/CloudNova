"""Live AWS account scanning (read-only) - the same Finding contract as everything else.

Split like the rest of CloudNova: a boto3 *collector* gathers a plain
:class:`AwsInventory` (read-only API calls), and pure *check* functions turn that
inventory into findings. The checks never call AWS, so they are fully testable
offline; the collector is the only part that needs credentials, and it only ever
reads (Describe/Get/List) - it never creates, modifies, or deletes anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cloudnova.checks._aws import SENSITIVE_PORTS, WORLD_CIDRS
from cloudnova.core.findings import Confidence, Finding, Location, Severity


@dataclass
class S3Bucket:
    name: str
    public_access_block: bool = False  # True only if all four blocks are on
    public_acl: bool = False
    encrypted: bool = True


@dataclass
class IamUser:
    name: str
    has_console_password: bool = False
    mfa_enabled: bool = False
    active_key_age_days: int | None = None


@dataclass
class SecurityGroup:
    id: str
    name: str = ""
    # Open ingress rules exposed to the world, as (from_port, to_port, cidr).
    world_ingress: list[tuple[int, int, str]] = field(default_factory=list)


@dataclass
class RdsInstance:
    id: str
    public: bool = False
    encrypted: bool = True


@dataclass
class AwsInventory:
    account: str = "unknown"
    buckets: list[S3Bucket] = field(default_factory=list)
    iam_users: list[IamUser] = field(default_factory=list)
    security_groups: list[SecurityGroup] = field(default_factory=list)
    rds: list[RdsInstance] = field(default_factory=list)


_KEY_AGE_LIMIT = 90


def check_s3(inv: AwsInventory) -> list[Finding]:
    out: list[Finding] = []
    for b in inv.buckets:
        loc = Location(path=f"arn:aws:s3:::{b.name}", resource=b.name)
        if b.public_acl or not b.public_access_block:
            out.append(
                Finding(
                    check_id="AWS_S3_PUBLIC",
                    title="S3 bucket is publicly accessible",
                    severity=Severity.CRITICAL if b.public_acl else Severity.HIGH,
                    confidence=Confidence.HIGH,
                    location=loc,
                    description=(
                        f"Bucket '{b.name}' has a public ACL"
                        if b.public_acl
                        else f"Bucket '{b.name}' does not enforce S3 Block Public Access."
                    ),
                    remediation="Enable S3 Block Public Access (all four settings) and remove "
                    "public ACLs/policies.",
                    cis_controls=["CIS AWS 2.1.5"],
                    mitre_attack=["T1530"],
                )
            )
        if not b.encrypted:
            out.append(
                Finding(
                    check_id="AWS_S3_NO_ENCRYPTION",
                    title="S3 bucket has no default encryption",
                    severity=Severity.MEDIUM,
                    location=loc,
                    description=f"Bucket '{b.name}' has no default server-side encryption.",
                    remediation="Enable default SSE (SSE-S3 or SSE-KMS) on the bucket.",
                    cis_controls=["CIS AWS 2.1.1"],
                )
            )
    return out


def check_iam(inv: AwsInventory) -> list[Finding]:
    out: list[Finding] = []
    for u in inv.iam_users:
        loc = Location(path=f"iam:user/{u.name}", resource=u.name)
        if u.has_console_password and not u.mfa_enabled:
            out.append(
                Finding(
                    check_id="AWS_IAM_NO_MFA",
                    title="IAM user has console access without MFA",
                    severity=Severity.HIGH,
                    location=loc,
                    description=f"User '{u.name}' can log in to the console but has no MFA device.",
                    remediation="Require and enroll an MFA device for every console user.",
                    cis_controls=["CIS AWS 1.10"],
                    mitre_attack=["T1078"],
                )
            )
        if u.active_key_age_days is not None and u.active_key_age_days > _KEY_AGE_LIMIT:
            out.append(
                Finding(
                    check_id="AWS_IAM_STALE_KEY",
                    title="IAM access key is older than 90 days",
                    severity=Severity.MEDIUM,
                    location=loc,
                    description=f"User '{u.name}' has an active access key {u.active_key_age_days} "
                    "days old.",
                    remediation="Rotate access keys every 90 days; prefer short-lived roles.",
                    cis_controls=["CIS AWS 1.14"],
                )
            )
    return out


def check_security_groups(inv: AwsInventory) -> list[Finding]:
    out: list[Finding] = []
    for sg in inv.security_groups:
        for from_port, to_port, cidr in sg.world_ingress:
            if cidr not in WORLD_CIDRS:
                continue
            hit = next((p for p in SENSITIVE_PORTS if from_port <= p <= to_port), None)
            sensitive = SENSITIVE_PORTS.get(hit) if hit is not None else None
            out.append(
                Finding(
                    check_id="AWS_SG_WORLD_INGRESS",
                    title=f"Security group open to the world on {sensitive or 'a port range'}",
                    severity=Severity.CRITICAL if sensitive else Severity.HIGH,
                    location=Location(
                        path=f"ec2:security-group/{sg.id}", resource=sg.name or sg.id
                    ),
                    description=f"Security group '{sg.id}' allows {cidr} to "
                    f"{from_port}-{to_port}" + (f" ({sensitive})" if sensitive else "") + ".",
                    remediation="Restrict ingress to specific trusted CIDRs; never expose admin/DB "
                    "ports to 0.0.0.0/0.",
                    cis_controls=["CIS AWS 5.2"],
                    mitre_attack=["T1190"],
                )
            )
    return out


def check_rds(inv: AwsInventory) -> list[Finding]:
    out: list[Finding] = []
    for db in inv.rds:
        loc = Location(path=f"rds:db/{db.id}", resource=db.id)
        if db.public:
            out.append(
                Finding(
                    check_id="AWS_RDS_PUBLIC",
                    title="RDS instance is publicly accessible",
                    severity=Severity.HIGH,
                    location=loc,
                    description=f"RDS instance '{db.id}' is marked publicly accessible.",
                    remediation="Disable public accessibility; use private subnets only.",
                    mitre_attack=["T1190"],
                )
            )
        if not db.encrypted:
            out.append(
                Finding(
                    check_id="AWS_RDS_NO_ENCRYPTION",
                    title="RDS instance is not encrypted at rest",
                    severity=Severity.MEDIUM,
                    location=loc,
                    description=f"RDS instance '{db.id}' has storage encryption disabled.",
                    remediation="Enable storage encryption (KMS) on the instance.",
                )
            )
    return out


_CHECKS = (check_s3, check_iam, check_security_groups, check_rds)


def analyze_aws(inv: AwsInventory) -> list[Finding]:
    """Run every AWS check over an inventory (pure, no network)."""
    findings: list[Finding] = []
    for check in _CHECKS:
        findings.extend(check(inv))
    findings.sort(key=lambda f: f.sort_key())
    return findings


def collect_inventory(profile: str | None = None, region: str | None = None) -> AwsInventory:
    """Gather a read-only inventory from a live AWS account (needs boto3 + credentials)."""
    from cloudnova.cloud._aws_collect import collect  # lazy: boto3 only needed here

    return collect(profile=profile, region=region)


def scan_aws(
    *,
    profile: str | None = None,
    region: str | None = None,
    inventory: AwsInventory | None = None,
) -> list[Finding]:
    """Scan a live AWS account (or a supplied inventory, for tests) and return findings."""
    inv = inventory if inventory is not None else collect_inventory(profile=profile, region=region)
    return analyze_aws(inv)
