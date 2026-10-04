"""Terraform rules for the Google Cloud provider.

CloudNova had no GCP coverage in infrastructure-as-code, so an estate written
against the google provider produced an empty report. These rules follow the
CIS Google Cloud Foundations Benchmark, grouped like the other packs: reach,
then data, then what a workload inherits.

GCP differs from AWS in one way worth encoding: a great deal of exposure is
expressed as an IAM binding to the pseudo-principals allUsers and
allAuthenticatedUsers rather than as a flag on the resource, so several rules
here inspect bindings instead of attributes.
"""

from __future__ import annotations

from collections.abc import Iterator

from cloudnova.checks._tf_base import AttributeCheck, TerraformCheck, first, missing, truthy
from cloudnova.checks.terraform_network import SENSITIVE_PORTS
from cloudnova.core.check import register
from cloudnova.core.findings import Confidence, Finding, Severity
from cloudnova.core.resource import CloudResource

# GCP's pseudo-principals. allUsers is anyone on the internet;
# allAuthenticatedUsers is anyone with any Google account, which is close enough
# to the same thing that CIS treats them together.
PUBLIC_PRINCIPALS = frozenset({"allUsers", "allAuthenticatedUsers"})

# Primitive roles predate IAM's fine-grained roles and are far too broad to
# grant in a production project.
PRIMITIVE_ROLES = {
    "roles/owner": "project owner",
    "roles/editor": "project editor",
}

WORLD_RANGES = frozenset({"0.0.0.0/0", "::/0"})


def _members(resource: CloudResource) -> list[str]:
    raw = resource.get("members")
    if isinstance(raw, list):
        return [str(first(m)) for m in raw]
    single = resource.get("member")
    return [str(first(single))] if single is not None else []


@register
class StorageBucketPublic(TerraformCheck):
    id = "GCP_BUCKET_PUBLIC"
    title = "Cloud Storage bucket is readable by anyone"
    severity = Severity.CRITICAL

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type not in {
            "google_storage_bucket_iam_member",
            "google_storage_bucket_iam_binding",
        }:
            return
        exposed = [m for m in _members(resource) if m in PUBLIC_PRINCIPALS]
        if not exposed:
            return
        role = str(first(resource.get("role")) or "unknown")
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Binding '{resource.name}' grants {role} to {', '.join(exposed)}, "
                "which makes the bucket's objects readable without any credential. "
                "This is the most common cause of GCP data exposure."
            ),
            remediation=(
                "Remove the allUsers and allAuthenticatedUsers members and grant "
                "access to named principals or a service account."
            ),
            evidence=f"{role} granted to {', '.join(exposed)}",
            cis_controls=["CIS GCP 5.1"],
            mitre_attack=["T1530"],
        )


@register
class StorageBucketNoUniformAccess(AttributeCheck):
    id = "GCP_BUCKET_NO_UNIFORM_ACCESS"
    title = "Cloud Storage bucket still allows per-object ACLs"
    severity = Severity.MEDIUM
    types = frozenset({"google_storage_bucket"})
    attribute = "uniform_bucket_level_access"
    description_template = (
        "Bucket '{name}' permits legacy per-object ACLs, so an object can be made "
        "public individually and bucket-level policy will not stop it."
    )
    remediation_text = "Set uniform_bucket_level_access = true."
    cis = ("CIS GCP 5.2",)
    mitre = ("T1530",)


@register
class StorageBucketNoVersioning(TerraformCheck):
    id = "GCP_BUCKET_NO_VERSIONING"
    title = "Cloud Storage bucket has versioning disabled"
    severity = Severity.MEDIUM

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "google_storage_bucket":
            return
        block = first(resource.get("versioning"))
        if isinstance(block, dict) and truthy(block.get("enabled")):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.MEDIUM,
            location=self.loc(resource),
            description=(
                f"Bucket '{resource.name}' has no versioning, so an overwrite or "
                "delete is final. This is the control that makes object-store "
                "ransomware survivable."
            ),
            remediation="Add versioning { enabled = true }.",
            evidence="versioning not enabled",
            cis_controls=[],
            mitre_attack=["T1485", "T1490"],
        )


@register
class FirewallSensitivePort(TerraformCheck):
    id = "GCP_FIREWALL_SENSITIVE_PORT_WORLD"
    title = "Firewall rule exposes a sensitive service to the internet"
    severity = Severity.CRITICAL

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "google_compute_firewall":
            return
        if str(first(resource.get("direction")) or "INGRESS").upper() != "INGRESS":
            return
        ranges = resource.get("source_ranges")
        if isinstance(ranges, str):
            ranges = [ranges]
        if not isinstance(ranges, list):
            return
        if not any(str(first(r)) in WORLD_RANGES for r in ranges):
            return

        allow = resource.get("allow")
        blocks = [allow] if isinstance(allow, dict) else allow
        if not isinstance(blocks, list):
            return
        for block in blocks:
            if not isinstance(block, dict):
                continue
            for port in self._ports(block):
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
                        f"Firewall '{resource.name}' allows 0.0.0.0/0 to reach port "
                        f"{port} ({service}). GCP firewall rules apply across the "
                        "whole VPC network, so this is broader than a single host."
                    ),
                    remediation=(
                        f"Restrict source_ranges for the {service} rule, or use "
                        "Identity-Aware Proxy for administrative access."
                    ),
                    evidence=f"0.0.0.0/0 -> {port}/{service}",
                    cis_controls=["CIS GCP 3.6", "CIS GCP 3.7"],
                    mitre_attack=["T1190", "T1133"],
                )

    def _ports(self, block: dict[str, object]) -> list[int]:
        raw = block.get("ports")
        if raw is None:
            # No ports means every port for that protocol.
            return sorted(SENSITIVE_PORTS)
        entries = raw if isinstance(raw, list) else [raw]
        ports: list[int] = []
        for entry in entries:
            text = str(first(entry) or "").strip()
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
class ComputeInstancePublicIp(TerraformCheck):
    id = "GCP_INSTANCE_PUBLIC_IP"
    title = "Compute instance has a public IP address"
    severity = Severity.MEDIUM

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "google_compute_instance":
            return
        interfaces = resource.get("network_interface")
        blocks = [interfaces] if isinstance(interfaces, dict) else interfaces
        if not isinstance(blocks, list):
            return
        for block in blocks:
            if not isinstance(block, dict):
                continue
            if "access_config" not in block:
                continue
            yield Finding(
                check_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.HIGH,
                location=self.loc(resource),
                description=(
                    f"Instance '{resource.name}' has an access_config block, which "
                    "assigns an external IP. Every service bound on the host becomes "
                    "internet-reachable subject only to firewall rules."
                ),
                remediation=(
                    "Remove access_config and reach the instance through Cloud NAT, "
                    "a bastion, or Identity-Aware Proxy."
                ),
                evidence="network_interface.access_config present",
                cis_controls=[],
                mitre_attack=["T1190"],
            )
            return


@register
class ComputeInstanceDefaultServiceAccount(TerraformCheck):
    id = "GCP_INSTANCE_FULL_API_SCOPE"
    title = "Compute instance has unrestricted API scope"
    severity = Severity.HIGH

    _FULL = "https://www.googleapis.com/auth/cloud-platform"

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "google_compute_instance":
            return
        account = first(resource.get("service_account"))
        if not isinstance(account, dict):
            return
        scopes = account.get("scopes")
        entries = scopes if isinstance(scopes, list) else [scopes]
        flat = [str(first(s)) for s in entries if s is not None]
        if not any(s in {self._FULL, "cloud-platform"} for s in flat):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Instance '{resource.name}' is granted the cloud-platform scope, so "
                "anything running on it can use the full API surface the attached "
                "service account is permitted. Landing on this host means inheriting "
                "the whole account."
            ),
            remediation=(
                "Grant only the specific scopes the workload needs, and attach a "
                "dedicated least-privilege service account."
            ),
            evidence="scopes include cloud-platform",
            cis_controls=["CIS GCP 4.2"],
            mitre_attack=["T1078", "T1098"],
        )


@register
class ComputeInstanceSerialPort(TerraformCheck):
    id = "GCP_INSTANCE_SERIAL_PORT"
    title = "Compute instance has interactive serial console enabled"
    severity = Severity.MEDIUM

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "google_compute_instance":
            return
        metadata = first(resource.get("metadata"))
        if not isinstance(metadata, dict):
            return
        if not truthy(metadata.get("serial-port-enable")):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Instance '{resource.name}' enables the interactive serial console, "
                "which is reachable from outside the VPC and bypasses firewall rules "
                "entirely."
            ),
            remediation='Set metadata serial-port-enable to "false" or remove it.',
            evidence="metadata.serial-port-enable is true",
            cis_controls=["CIS GCP 4.4"],
            mitre_attack=["T1133"],
        )


@register
class ComputeInstanceNoShieldedVm(TerraformCheck):
    id = "GCP_INSTANCE_NO_SHIELDED_VM"
    title = "Compute instance does not use Shielded VM"
    severity = Severity.LOW

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "google_compute_instance":
            return
        block = first(resource.get("shielded_instance_config"))
        if isinstance(block, dict) and truthy(block.get("enable_integrity_monitoring")):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.MEDIUM,
            location=self.loc(resource),
            description=(
                f"Instance '{resource.name}' has no Shielded VM configuration, so "
                "there is no secure boot or integrity monitoring to detect a "
                "rootkit or a tampered boot sequence."
            ),
            remediation=(
                "Add shielded_instance_config with enable_secure_boot, enable_vtpm "
                "and enable_integrity_monitoring set to true."
            ),
            evidence="shielded_instance_config absent or incomplete",
            cis_controls=["CIS GCP 4.8"],
            mitre_attack=["T1542"],
        )


@register
class SqlInstancePublicIp(TerraformCheck):
    id = "GCP_SQL_PUBLIC_IP"
    title = "Cloud SQL instance has a public IP"
    severity = Severity.HIGH

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "google_sql_database_instance":
            return
        settings = first(resource.get("settings"))
        if not isinstance(settings, dict):
            return
        ip_config = first(settings.get("ip_configuration"))
        if not isinstance(ip_config, dict):
            return
        if not truthy(ip_config.get("ipv4_enabled")):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Cloud SQL instance '{resource.name}' has a public IPv4 address. "
                "Combined with a permissive authorized network this puts the "
                "database on the internet."
            ),
            remediation=(
                "Set ipv4_enabled = false and use private IP with a VPC peering, or "
                "the Cloud SQL Auth proxy."
            ),
            evidence="settings.ip_configuration.ipv4_enabled = true",
            cis_controls=["CIS GCP 6.6"],
            mitre_attack=["T1190"],
        )


@register
class SqlInstanceWorldAuthorized(TerraformCheck):
    id = "GCP_SQL_WORLD_AUTHORIZED"
    title = "Cloud SQL authorizes the entire internet"
    severity = Severity.CRITICAL

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "google_sql_database_instance":
            return
        settings = first(resource.get("settings"))
        if not isinstance(settings, dict):
            return
        ip_config = first(settings.get("ip_configuration"))
        if not isinstance(ip_config, dict):
            return
        networks = ip_config.get("authorized_networks")
        blocks = [networks] if isinstance(networks, dict) else networks
        if not isinstance(blocks, list):
            return
        for block in blocks:
            if not isinstance(block, dict):
                continue
            if str(first(block.get("value")) or "") not in WORLD_RANGES:
                continue
            yield Finding(
                check_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.HIGH,
                location=self.loc(resource),
                description=(
                    f"Cloud SQL instance '{resource.name}' authorizes 0.0.0.0/0, so "
                    "the database accepts connections from any address on the "
                    "internet and only the password stands in the way."
                ),
                remediation=(
                    "Replace the authorized network with specific CIDRs, or move to "
                    "private IP and remove public access."
                ),
                evidence="authorized_networks includes 0.0.0.0/0",
                cis_controls=["CIS GCP 6.5"],
                mitre_attack=["T1190", "T1110"],
            )
            return


@register
class SqlInstanceNoSsl(TerraformCheck):
    id = "GCP_SQL_SSL_NOT_REQUIRED"
    title = "Cloud SQL does not require SSL"
    severity = Severity.HIGH

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "google_sql_database_instance":
            return
        settings = first(resource.get("settings"))
        if not isinstance(settings, dict):
            return
        ip_config = first(settings.get("ip_configuration"))
        if not isinstance(ip_config, dict):
            return
        # Only meaningful when the instance is reachable over IP at all.
        if not truthy(ip_config.get("ipv4_enabled")):
            return
        if truthy(ip_config.get("require_ssl")):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Cloud SQL instance '{resource.name}' has a public IP and does not "
                "require SSL, so credentials and query results can cross the "
                "internet in cleartext."
            ),
            remediation="Set require_ssl = true, or remove the public IP.",
            evidence="require_ssl not set with ipv4_enabled = true",
            cis_controls=["CIS GCP 6.4"],
            mitre_attack=["T1040"],
        )


@register
class GkeNoPrivateNodes(TerraformCheck):
    id = "GCP_GKE_PUBLIC_NODES"
    title = "GKE cluster nodes are not private"
    severity = Severity.MEDIUM

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "google_container_cluster":
            return
        block = first(resource.get("private_cluster_config"))
        if isinstance(block, dict) and truthy(block.get("enable_private_nodes")):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.MEDIUM,
            location=self.loc(resource),
            description=(
                f"Cluster '{resource.name}' has no private_cluster_config with "
                "enable_private_nodes, so nodes receive public addresses and every "
                "workload on them is one firewall rule from exposure."
            ),
            remediation=(
                "Add private_cluster_config with enable_private_nodes = true, and "
                "use Cloud NAT for egress."
            ),
            evidence="enable_private_nodes not set",
            cis_controls=["CIS GCP 7.15"],
            mitre_attack=["T1190"],
        )


@register
class GkeLegacyAbac(TerraformCheck):
    id = "GCP_GKE_LEGACY_ABAC"
    title = "GKE cluster has legacy ABAC enabled"
    severity = Severity.HIGH

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "google_container_cluster":
            return
        block = first(resource.get("enable_legacy_abac"))
        if not truthy(block):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Cluster '{resource.name}' enables legacy ABAC, which grants broad "
                "permissions that bypass Kubernetes RBAC entirely."
            ),
            remediation="Set enable_legacy_abac = false and rely on RBAC.",
            evidence="enable_legacy_abac = true",
            cis_controls=["CIS GCP 7.3"],
            mitre_attack=["T1078"],
        )


@register
class IamPrimitiveRole(TerraformCheck):
    id = "GCP_IAM_PRIMITIVE_ROLE"
    title = "A primitive IAM role is granted at project level"
    severity = Severity.HIGH

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type not in {
            "google_project_iam_member",
            "google_project_iam_binding",
        }:
            return
        role = str(first(resource.get("role")) or "")
        label = PRIMITIVE_ROLES.get(role)
        if label is None:
            return
        who = ", ".join(_members(resource)) or "the named members"
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Binding '{resource.name}' grants {label} over the whole project to "
                f"{who}. Primitive roles predate fine-grained IAM and are far "
                "broader than any workload needs."
            ),
            remediation=(
                "Replace it with predefined or custom roles scoped to the specific "
                "services and resources in use."
            ),
            evidence=f"{role} granted to {who}",
            cis_controls=["CIS GCP 1.5"],
            mitre_attack=["T1078", "T1098"],
        )


@register
class IamPublicPrincipal(TerraformCheck):
    id = "GCP_IAM_PUBLIC_PRINCIPAL"
    title = "An IAM binding grants access to all users"
    severity = Severity.CRITICAL

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if not resource.type.startswith("google_") or "iam_" not in resource.type:
            return
        # Bucket bindings have their own, more specific rule.
        if resource.type.startswith("google_storage_bucket_iam"):
            return
        exposed = [m for m in _members(resource) if m in PUBLIC_PRINCIPALS]
        if not exposed:
            return
        role = str(first(resource.get("role")) or "unknown")
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Binding '{resource.name}' grants {role} to {', '.join(exposed)}. "
                "allUsers is anyone on the internet and allAuthenticatedUsers is "
                "anyone with a Google account, so neither is a meaningful boundary."
            ),
            remediation="Grant the role to named principals or a service account.",
            evidence=f"{role} granted to {', '.join(exposed)}",
            cis_controls=["CIS GCP 1.1"],
            mitre_attack=["T1078"],
        )


@register
class ServiceAccountKey(TerraformCheck):
    id = "GCP_SERVICE_ACCOUNT_KEY"
    title = "A long-lived service account key is declared in code"
    severity = Severity.HIGH

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "google_service_account_key":
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.MEDIUM,
            location=self.loc(resource),
            description=(
                f"Service account key '{resource.name}' is a static credential that "
                "does not expire. Keys like this leak into git, CI logs and laptops, "
                "and Google's own guidance is to avoid creating them."
            ),
            remediation=(
                "Use Workload Identity Federation for external systems, or Workload "
                "Identity for GKE, so no key material exists to leak."
            ),
            evidence="google_service_account_key declared",
            cis_controls=["CIS GCP 1.4"],
            mitre_attack=["T1552.001"],
        )


@register
class KmsNoRotation(TerraformCheck):
    id = "GCP_KMS_NO_ROTATION"
    title = "KMS crypto key has no rotation period"
    severity = Severity.LOW

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "google_kms_crypto_key":
            return
        if not missing(resource.get("rotation_period")):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Key '{resource.name}' never rotates, so the blast radius of any "
                "past key compromise never shrinks."
            ),
            remediation='Set rotation_period to 90 days or less, for example "7776000s".',
            evidence="rotation_period absent",
            cis_controls=["CIS GCP 1.10"],
            mitre_attack=["T1552"],
        )


@register
class BigQueryDatasetPublic(TerraformCheck):
    id = "GCP_BIGQUERY_PUBLIC"
    title = "BigQuery dataset is accessible to all users"
    severity = Severity.CRITICAL

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "google_bigquery_dataset":
            return
        access = resource.get("access")
        blocks = [access] if isinstance(access, dict) else access
        if not isinstance(blocks, list):
            return
        for block in blocks:
            if not isinstance(block, dict):
                continue
            principal = str(first(block.get("special_group")) or "") or str(
                first(block.get("iam_member")) or ""
            )
            if principal not in PUBLIC_PRINCIPALS and principal != "allAuthenticatedUsers":
                continue
            yield Finding(
                check_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.HIGH,
                location=self.loc(resource),
                description=(
                    f"Dataset '{resource.name}' grants access to {principal}. "
                    "Analytics datasets aggregate data from across the business, so "
                    "exposure here is usually broader than any single table."
                ),
                remediation="Remove the public grant and use named principals.",
                evidence=f"access grants {principal}",
                cis_controls=["CIS GCP 7.1"],
                mitre_attack=["T1530"],
            )
            return
