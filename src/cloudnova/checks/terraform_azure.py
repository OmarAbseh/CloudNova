"""Terraform rules for the Azure provider.

CloudNova had no Azure coverage in infrastructure-as-code at all, so an estate
written against azurerm produced an empty report. These rules follow the CIS
Microsoft Azure Foundations Benchmark and the Azure security baseline, grouped
the same way as the AWS packs: can it be reached, can the data be read, what
does the workload inherit.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from cloudnova.checks._tf_base import AttributeCheck, TerraformCheck, first, missing, truthy
from cloudnova.checks.terraform_network import SENSITIVE_PORTS
from cloudnova.core.check import register
from cloudnova.core.findings import Confidence, Finding, Severity
from cloudnova.core.resource import CloudResource

# Azure accepts these as "any address" in a SQL firewall rule. The 0.0.0.0 pair
# is the special "allow all Azure services" entry, which is far broader than
# most people realise: it admits every tenant in the region, not just yours.
AZURE_ANY_ADDRESS = frozenset({"0.0.0.0", "0.0.0.0/0", "*", "Internet", "Any"})

_TLS_OK = frozenset({"TLS1_2", "TLS1_3"})


@register
class StorageInsecureTransfer(AttributeCheck):
    id = "AZ_STORAGE_HTTP_ALLOWED"
    title = "Storage account allows plaintext HTTP"
    severity = Severity.HIGH
    types = frozenset({"azurerm_storage_account"})
    attribute = "enable_https_traffic_only"
    description_template = (
        "Storage account '{name}' accepts unencrypted connections, so access keys "
        "and blob contents can be read in transit."
    )
    remediation_text = (
        "Set enable_https_traffic_only = true (https_traffic_only_enabled on newer providers)."
    )
    cis = ("CIS Azure 3.1",)
    mitre = ("T1040",)


@register
class StorageWeakTls(TerraformCheck):
    id = "AZ_STORAGE_WEAK_TLS"
    title = "Storage account permits obsolete TLS"
    severity = Severity.MEDIUM

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "azurerm_storage_account":
            return
        version = str(first(resource.get("min_tls_version")) or "TLS1_0")
        if version in _TLS_OK:
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Storage account '{resource.name}' sets min_tls_version = "
                f'"{version}", which still negotiates a deprecated protocol that '
                "fails PCI DSS."
            ),
            remediation='Set min_tls_version = "TLS1_2".',
            evidence=f'min_tls_version = "{version}"',
            cis_controls=["CIS Azure 3.15"],
            mitre_attack=["T1040"],
        )


@register
class StoragePublicBlobs(TerraformCheck):
    id = "AZ_STORAGE_PUBLIC_BLOBS"
    title = "Storage account permits public blob containers"
    severity = Severity.HIGH

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "azurerm_storage_account":
            return
        # Two provider generations spell this differently; both mean the same.
        for attr in ("allow_nested_items_to_be_public", "allow_blob_public_access"):
            raw = resource.get(attr)
            if raw is not None and truthy(raw):
                yield Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=self.severity,
                    confidence=Confidence.HIGH,
                    location=self.loc(resource),
                    description=(
                        f"Storage account '{resource.name}' allows containers to be "
                        "made publicly readable. Anonymous blob exposure is the "
                        "single most common source of Azure data leaks."
                    ),
                    remediation=f"Set {attr} = false and grant access with SAS or RBAC.",
                    evidence=f"{attr} = true",
                    cis_controls=["CIS Azure 3.7"],
                    mitre_attack=["T1530"],
                )
                return


@register
class SqlServerPublicAccess(AttributeCheck):
    id = "AZ_SQL_PUBLIC_ACCESS"
    title = "SQL server is reachable from the public network"
    severity = Severity.HIGH
    types = frozenset({"azurerm_mssql_server", "azurerm_sql_server"})
    attribute = "public_network_access_enabled"
    invert = True
    description_template = (
        "SQL server '{name}' has a public endpoint. Combined with a permissive "
        "firewall rule this puts the database on the internet."
    )
    remediation_text = "Set public_network_access_enabled = false and use a private endpoint."
    cis = ("CIS Azure 4.2.1",)
    mitre = ("T1190",)


@register
class SqlFirewallAllowsAll(TerraformCheck):
    id = "AZ_SQL_FIREWALL_ANY"
    title = "SQL firewall rule allows any address"
    severity = Severity.CRITICAL

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type not in {
            "azurerm_sql_firewall_rule",
            "azurerm_mssql_firewall_rule",
            "azurerm_postgresql_firewall_rule",
            "azurerm_mysql_firewall_rule",
        }:
            return
        start = str(first(resource.get("start_ip_address")) or "")
        end = str(first(resource.get("end_ip_address")) or "")
        spans_everything = start == "0.0.0.0" and end in {"0.0.0.0", "255.255.255.255"}
        if start not in AZURE_ANY_ADDRESS and not spans_everything:
            return
        azure_services = start == "0.0.0.0" and end == "0.0.0.0"
        detail = (
            "This is the special 'allow all Azure services' entry, which admits "
            "every tenant in the region rather than only your own subscription."
            if azure_services
            else "This admits the entire internet."
        )
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(f"Firewall rule '{resource.name}' spans {start} to {end}. {detail}"),
            remediation=(
                "Replace it with the specific client addresses that need access, or "
                "use a private endpoint and remove public access entirely."
            ),
            evidence=f"{start} - {end}",
            cis_controls=["CIS Azure 4.1.1"],
            mitre_attack=["T1190"],
        )


@register
class SqlNoAuditing(TerraformCheck):
    id = "AZ_SQL_NO_AUDITING"
    title = "SQL server has no auditing policy"
    severity = Severity.MEDIUM

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type not in {"azurerm_mssql_server", "azurerm_sql_server"}:
            return
        if not missing(resource.get("extended_auditing_policy")):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.MEDIUM,
            location=self.loc(resource),
            description=(
                f"SQL server '{resource.name}' has no auditing policy in this "
                "configuration, so queries against sensitive data leave no record "
                "and a breach cannot be reconstructed."
            ),
            remediation=(
                "Add an extended_auditing_policy, or an "
                "azurerm_mssql_server_extended_auditing_policy resource."
            ),
            evidence="extended_auditing_policy absent",
            cis_controls=["CIS Azure 4.1.3"],
            mitre_attack=["T1562"],
        )


@register
class NetworkSecurityGroupSensitivePort(TerraformCheck):
    id = "AZ_NSG_SENSITIVE_PORT_WORLD"
    title = "Network security group exposes a sensitive service to the internet"
    severity = Severity.CRITICAL

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "azurerm_network_security_rule":
            return
        if str(first(resource.get("direction")) or "").lower() != "inbound":
            return
        if str(first(resource.get("access")) or "").lower() != "allow":
            return
        prefix = str(first(resource.get("source_address_prefix")) or "")
        if prefix not in AZURE_ANY_ADDRESS:
            return
        for port in self._ports(resource):
            service = SENSITIVE_PORTS.get(port)
            if service is None:
                continue
            yield Finding(
                check_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.HIGH,
                location=self.loc(resource),
                description=(
                    f"Rule '{resource.name}' allows {prefix} to reach port {port} "
                    f"({service}). This is directly scannable from the internet."
                ),
                remediation=(
                    f"Restrict source_address_prefix for the {service} rule, or use "
                    "Azure Bastion instead of exposing management ports."
                ),
                evidence=f"{prefix} -> {port}/{service}",
                cis_controls=["CIS Azure 6.1", "CIS Azure 6.2"],
                mitre_attack=["T1190", "T1133"],
            )

    def _ports(self, resource: CloudResource) -> list[int]:
        raw: list[Any] = []
        single = resource.get("destination_port_range")
        if single is not None:
            raw.append(single)
        many = resource.get("destination_port_ranges")
        if isinstance(many, list):
            raw.extend(many)
        ports: list[int] = []
        for entry in raw:
            text = str(first(entry) or "").strip()
            if text == "*":
                return sorted(SENSITIVE_PORTS)
            if "-" in text:
                try:
                    lo, hi = (int(x) for x in text.split("-", 1))
                except ValueError:
                    continue
                ports.extend(p for p in SENSITIVE_PORTS if lo <= p <= hi)
                continue
            try:
                ports.append(int(text))
            except ValueError:
                continue
        return ports


@register
class KeyVaultNoPurgeProtection(AttributeCheck):
    id = "AZ_KEYVAULT_NO_PURGE_PROTECTION"
    title = "Key Vault has no purge protection"
    severity = Severity.MEDIUM
    types = frozenset({"azurerm_key_vault"})
    attribute = "purge_protection_enabled"
    description_template = (
        "Key Vault '{name}' can be permanently deleted along with every key and "
        "secret in it, which makes any data those keys protect unrecoverable."
    )
    remediation_text = "Set purge_protection_enabled = true and soft_delete_retention_days."
    cis = ("CIS Azure 8.5",)
    mitre = ("T1485",)


@register
class KeyVaultPublicAccess(TerraformCheck):
    id = "AZ_KEYVAULT_PUBLIC_ACCESS"
    title = "Key Vault is reachable from any network"
    severity = Severity.HIGH

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "azurerm_key_vault":
            return
        acls = first(resource.get("network_acls"))
        if isinstance(acls, dict):
            default = str(first(acls.get("default_action")) or "").lower()
            if default == "deny":
                return
        elif missing(resource.get("public_network_access_enabled")):
            # No ACLs declared at all: the vault defaults to open.
            pass
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.MEDIUM,
            location=self.loc(resource),
            description=(
                f"Key Vault '{resource.name}' has no network ACL defaulting to deny, "
                "so the vault endpoint accepts connections from any network. A leaked "
                "credential is then usable from anywhere."
            ),
            remediation=(
                'Add network_acls with default_action = "Deny" and allow only your '
                "subnets, or use a private endpoint."
            ),
            evidence="network_acls default_action is not Deny",
            cis_controls=["CIS Azure 8.6"],
            mitre_attack=["T1552"],
        )


@register
class AksNoRbac(TerraformCheck):
    id = "AZ_AKS_RBAC_DISABLED"
    title = "AKS cluster has Kubernetes RBAC disabled"
    severity = Severity.HIGH

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "azurerm_kubernetes_cluster":
            return
        raw = resource.get("role_based_access_control_enabled")
        if raw is None or truthy(raw):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Cluster '{resource.name}' disables Kubernetes RBAC, so any "
                "authenticated principal has unrestricted control of every workload "
                "and secret in the cluster."
            ),
            remediation="Set role_based_access_control_enabled = true.",
            evidence="role_based_access_control_enabled = false",
            cis_controls=["CIS Azure 9.1"],
            mitre_attack=["T1078"],
        )


@register
class AksPublicApi(TerraformCheck):
    id = "AZ_AKS_PUBLIC_API"
    title = "AKS API server is public and unrestricted"
    severity = Severity.HIGH

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "azurerm_kubernetes_cluster":
            return
        if truthy(resource.get("private_cluster_enabled")):
            return
        allowed = resource.get("api_server_authorized_ip_ranges")
        if isinstance(allowed, list) and allowed:
            return
        access = first(resource.get("api_server_access_profile"))
        if isinstance(access, dict) and access.get("authorized_ip_ranges"):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.MEDIUM,
            location=self.loc(resource),
            description=(
                f"Cluster '{resource.name}' is not a private cluster and has no "
                "authorized IP ranges, so its Kubernetes API is reachable from the "
                "internet."
            ),
            remediation=(
                "Set private_cluster_enabled = true, or list your office and CI "
                "ranges in api_server_authorized_ip_ranges."
            ),
            evidence="not private and no authorized IP ranges",
            cis_controls=[],
            mitre_attack=["T1190"],
        )


@register
class AppServiceHttpAllowed(AttributeCheck):
    id = "AZ_APPSERVICE_HTTP_ALLOWED"
    title = "App Service does not require HTTPS"
    severity = Severity.MEDIUM
    types = frozenset({"azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app"})
    attribute = "https_only"
    description_template = (
        "App '{name}' serves plaintext HTTP, so session cookies and credentials "
        "cross the network readable."
    )
    remediation_text = "Set https_only = true."
    cis = ("CIS Azure 10.1",)
    mitre = ("T1040",)


@register
class ManagedDiskNoEncryption(TerraformCheck):
    id = "AZ_DISK_NO_CMK"
    title = "Managed disk is not encrypted with a customer-managed key"
    severity = Severity.LOW

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "azurerm_managed_disk":
            return
        if not missing(resource.get("disk_encryption_set_id")):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.MEDIUM,
            location=self.loc(resource),
            description=(
                f"Disk '{resource.name}' relies on platform-managed keys. The data is "
                "encrypted, but you cannot rotate, audit or revoke the key, so key "
                "access cannot be separated from disk access."
            ),
            remediation="Set disk_encryption_set_id to a disk encryption set you own.",
            evidence="disk_encryption_set_id absent",
            cis_controls=["CIS Azure 7.3"],
            mitre_attack=["T1530"],
        )


@register
class CosmosPublicAccess(AttributeCheck):
    id = "AZ_COSMOS_PUBLIC_ACCESS"
    title = "Cosmos DB account is reachable from the public network"
    severity = Severity.HIGH
    types = frozenset({"azurerm_cosmosdb_account"})
    attribute = "public_network_access_enabled"
    invert = True
    description_template = (
        "Cosmos account '{name}' has a public endpoint, so a leaked key is usable "
        "from anywhere on the internet."
    )
    remediation_text = "Set public_network_access_enabled = false and use a private endpoint."
    cis = ()
    mitre = ("T1530",)


@register
class VmPasswordAuth(TerraformCheck):
    id = "AZ_VM_PASSWORD_AUTH"
    title = "Linux virtual machine allows password authentication"
    severity = Severity.MEDIUM

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type not in {
            "azurerm_linux_virtual_machine",
            "azurerm_linux_virtual_machine_scale_set",
        }:
            return
        raw = resource.get("disable_password_authentication")
        if raw is None or truthy(raw):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"VM '{resource.name}' accepts password authentication over SSH, which "
                "is brute-forceable and cannot be revoked centrally the way a key can."
            ),
            remediation=("Set disable_password_authentication = true and supply an admin_ssh_key."),
            evidence="disable_password_authentication = false",
            cis_controls=[],
            mitre_attack=["T1110"],
        )


@register
class PostgresSslDisabled(TerraformCheck):
    id = "AZ_POSTGRES_SSL_OFF"
    title = "PostgreSQL server does not enforce SSL"
    severity = Severity.HIGH

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type not in {"azurerm_postgresql_server", "azurerm_mysql_server"}:
            return
        raw = resource.get("ssl_enforcement_enabled")
        if raw is None or truthy(raw):
            return
        engine = "PostgreSQL" if "postgresql" in resource.type else "MySQL"
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"{engine} server '{resource.name}' does not enforce SSL, so "
                "credentials and query results cross the network in cleartext."
            ),
            remediation="Set ssl_enforcement_enabled = true.",
            evidence="ssl_enforcement_enabled = false",
            cis_controls=["CIS Azure 4.3.1"],
            mitre_attack=["T1040"],
        )
