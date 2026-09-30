"""Live Azure subscription scanning (read-only), mirroring the AWS design.

Pure checks over a plain :class:`AzureInventory`; the SDK collector is isolated and
lazy-imported so the checks stay testable offline. The collector only reads.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cloudnova.checks._aws import SENSITIVE_PORTS
from cloudnova.core.findings import Confidence, Finding, Location, Severity

_WORLD = {"*", "0.0.0.0/0", "internet", "::/0"}


@dataclass
class StorageAccount:
    name: str
    allow_blob_public_access: bool = False
    https_only: bool = True
    encrypted: bool = True


@dataclass
class NetworkSecurityGroup:
    name: str
    # Inbound allow rules exposed to the internet, as (name, port_from, port_to, source).
    world_inbound: list[tuple[str, int, int, str]] = field(default_factory=list)


@dataclass
class SqlServer:
    name: str
    public_network_access: bool = False


@dataclass
class AzureInventory:
    subscription: str = "unknown"
    storage_accounts: list[StorageAccount] = field(default_factory=list)
    nsgs: list[NetworkSecurityGroup] = field(default_factory=list)
    sql_servers: list[SqlServer] = field(default_factory=list)


def check_storage(inv: AzureInventory) -> list[Finding]:
    out: list[Finding] = []
    for sa in inv.storage_accounts:
        loc = Location(path=f"azure:storage/{sa.name}", resource=sa.name)
        if sa.allow_blob_public_access:
            out.append(
                Finding(
                    check_id="AZ_STORAGE_PUBLIC_BLOB",
                    title="Storage account allows public blob access",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    location=loc,
                    description=f"Storage account '{sa.name}' permits anonymous public blobs.",
                    remediation="Set 'allowBlobPublicAccess' to false unless hosting needs it.",
                    mitre_attack=["T1530"],
                )
            )
        if not sa.https_only:
            out.append(
                Finding(
                    check_id="AZ_STORAGE_NO_HTTPS",
                    title="Storage account allows plaintext HTTP",
                    severity=Severity.MEDIUM,
                    location=loc,
                    description=f"Storage account '{sa.name}' does not enforce HTTPS-only traffic.",
                    remediation="Enable 'supportsHttpsTrafficOnly' on the storage account.",
                )
            )
        if not sa.encrypted:
            out.append(
                Finding(
                    check_id="AZ_STORAGE_NO_ENCRYPTION",
                    title="Storage account is not encrypted",
                    severity=Severity.MEDIUM,
                    location=loc,
                    description=f"Storage account '{sa.name}' has encryption disabled.",
                    remediation="Enable encryption at rest on the storage account.",
                )
            )
    return out


def check_nsgs(inv: AzureInventory) -> list[Finding]:
    out: list[Finding] = []
    for nsg in inv.nsgs:
        for rule, from_port, to_port, source in nsg.world_inbound:
            if source.lower() not in _WORLD:
                continue
            hit = next((p for p in SENSITIVE_PORTS if from_port <= p <= to_port), None)
            sensitive = SENSITIVE_PORTS.get(hit) if hit is not None else None
            out.append(
                Finding(
                    check_id="AZ_NSG_WORLD_INBOUND",
                    title=f"NSG open to the internet on {sensitive or 'a port range'}",
                    severity=Severity.CRITICAL if sensitive else Severity.HIGH,
                    location=Location(path=f"azure:nsg/{nsg.name}", resource=nsg.name),
                    description=f"NSG '{nsg.name}' rule '{rule}' allows {source} to "
                    f"{from_port}-{to_port}" + (f" ({sensitive})" if sensitive else "") + ".",
                    remediation="Restrict inbound rules to specific source ranges; never expose "
                    "admin/DB ports to the internet.",
                    mitre_attack=["T1190"],
                )
            )
    return out


def check_sql(inv: AzureInventory) -> list[Finding]:
    out: list[Finding] = []
    for srv in inv.sql_servers:
        if srv.public_network_access:
            out.append(
                Finding(
                    check_id="AZ_SQL_PUBLIC",
                    title="Azure SQL server allows public network access",
                    severity=Severity.HIGH,
                    location=Location(path=f"azure:sql/{srv.name}", resource=srv.name),
                    description=f"SQL server '{srv.name}' has public network access enabled.",
                    remediation="Disable public network access; use private endpoints/VNet rules.",
                    mitre_attack=["T1190"],
                )
            )
    return out


_CHECKS = (check_storage, check_nsgs, check_sql)


def analyze_azure(inv: AzureInventory) -> list[Finding]:
    """Run every Azure check over an inventory (pure, no network)."""
    findings: list[Finding] = []
    for check in _CHECKS:
        findings.extend(check(inv))
    findings.sort(key=lambda f: f.sort_key())
    return findings


def scan_azure(
    *, subscription_id: str | None = None, inventory: AzureInventory | None = None
) -> list[Finding]:
    """Scan a live Azure subscription (or a supplied inventory, for tests)."""
    if inventory is None:
        from cloudnova.cloud._azure_collect import collect  # lazy: SDK only needed here

        inventory = collect(subscription_id=subscription_id)
    return analyze_azure(inventory)
