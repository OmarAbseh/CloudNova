"""Live GCP project scanning (read-only), mirroring the AWS/Azure design.

Pure checks over a plain :class:`GcpInventory`; the SDK collector is isolated and
lazy-imported so the checks stay testable offline. The collector only reads.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cloudnova.checks._aws import SENSITIVE_PORTS
from cloudnova.core.findings import Confidence, Finding, Location, Severity

_WORLD = {"0.0.0.0/0", "::/0"}


@dataclass
class GcsBucket:
    name: str
    public: bool = False  # allUsers / allAuthenticatedUsers in IAM
    uniform_access: bool = True


@dataclass
class FirewallRule:
    name: str
    # Allowed ingress from the internet, as (from_port, to_port, source_range).
    world_ingress: list[tuple[int, int, str]] = field(default_factory=list)


@dataclass
class CloudSqlInstance:
    name: str
    public_ip: bool = False
    requires_ssl: bool = True


@dataclass
class GcpInventory:
    project: str = "unknown"
    buckets: list[GcsBucket] = field(default_factory=list)
    firewalls: list[FirewallRule] = field(default_factory=list)
    sql: list[CloudSqlInstance] = field(default_factory=list)


def check_storage(inv: GcpInventory) -> list[Finding]:
    out: list[Finding] = []
    for b in inv.buckets:
        loc = Location(path=f"gcs://{b.name}", resource=b.name)
        if b.public:
            out.append(
                Finding(
                    check_id="GCP_GCS_PUBLIC",
                    title="Cloud Storage bucket is public",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    location=loc,
                    description=f"Bucket '{b.name}' grants access to allUsers/allAuthUsers.",
                    remediation="Remove allUsers/allAuthenticatedUsers IAM bindings.",
                    mitre_attack=["T1530"],
                )
            )
        if not b.uniform_access:
            out.append(
                Finding(
                    check_id="GCP_GCS_NO_UNIFORM_ACCESS",
                    title="Cloud Storage bucket allows fine-grained ACLs",
                    severity=Severity.LOW,
                    location=loc,
                    description=f"Bucket '{b.name}' does not enforce uniform bucket-level access.",
                    remediation="Enable uniform bucket-level access to prevent object-ACL drift.",
                )
            )
    return out


def check_firewalls(inv: GcpInventory) -> list[Finding]:
    out: list[Finding] = []
    for fw in inv.firewalls:
        for from_port, to_port, cidr in fw.world_ingress:
            if cidr not in _WORLD:
                continue
            hit = next((p for p in SENSITIVE_PORTS if from_port <= p <= to_port), None)
            sensitive = SENSITIVE_PORTS.get(hit) if hit is not None else None
            out.append(
                Finding(
                    check_id="GCP_FIREWALL_WORLD_INGRESS",
                    title=f"Firewall open to the internet on {sensitive or 'a port range'}",
                    severity=Severity.CRITICAL if sensitive else Severity.HIGH,
                    location=Location(path=f"gcp:firewall/{fw.name}", resource=fw.name),
                    description=f"Firewall '{fw.name}' allows {cidr} to {from_port}-{to_port}"
                    + (f" ({sensitive})" if sensitive else "")
                    + ".",
                    remediation="Restrict source ranges; never expose admin/DB ports to 0.0.0.0/0.",
                    mitre_attack=["T1190"],
                )
            )
    return out


def check_sql(inv: GcpInventory) -> list[Finding]:
    out: list[Finding] = []
    for db in inv.sql:
        loc = Location(path=f"gcp:sql/{db.name}", resource=db.name)
        if db.public_ip:
            out.append(
                Finding(
                    check_id="GCP_SQL_PUBLIC_IP",
                    title="Cloud SQL instance has a public IP",
                    severity=Severity.HIGH,
                    location=loc,
                    description=f"Cloud SQL '{db.name}' is reachable over a public IP.",
                    remediation="Use private IP / Cloud SQL Auth Proxy; disable the public IP.",
                    mitre_attack=["T1190"],
                )
            )
        if not db.requires_ssl:
            out.append(
                Finding(
                    check_id="GCP_SQL_NO_SSL",
                    title="Cloud SQL instance does not require SSL",
                    severity=Severity.MEDIUM,
                    location=loc,
                    description=f"Cloud SQL '{db.name}' accepts unencrypted connections.",
                    remediation="Require SSL/TLS for all Cloud SQL connections.",
                )
            )
    return out


_CHECKS = (check_storage, check_firewalls, check_sql)


def analyze_gcp(inv: GcpInventory) -> list[Finding]:
    """Run every GCP check over an inventory (pure, no network)."""
    findings: list[Finding] = []
    for check in _CHECKS:
        findings.extend(check(inv))
    findings.sort(key=lambda f: f.sort_key())
    return findings


def scan_gcp(*, project: str | None = None, inventory: GcpInventory | None = None) -> list[Finding]:
    """Scan a live GCP project (or a supplied inventory, for tests)."""
    if inventory is None:
        from cloudnova.cloud._gcp_collect import collect  # lazy: SDK only needed here

        inventory = collect(project=project)
    return analyze_gcp(inventory)
