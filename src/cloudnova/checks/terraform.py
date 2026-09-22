"""Security checks for Terraform (AWS provider).

Each check iterates the normalized :class:`CloudResource` list on a terraform
artifact and yields findings. Rules are mapped to CIS AWS Benchmark controls and
MITRE ATT&CK techniques so output is audit-ready. Adding a rule is one class +
one registration; the engine is untouched.
"""

from __future__ import annotations

from abc import abstractmethod
from collections.abc import Iterator
from typing import Any

from cloudnova.checks import _aws
from cloudnova.core.artifact import Artifact
from cloudnova.core.check import Check, register
from cloudnova.core.findings import Confidence, Finding, Location, Severity
from cloudnova.core.parsers.terraform import resolve_jsonencode
from cloudnova.core.resource import CloudResource


def _resources(artifact: Artifact) -> list[CloudResource]:
    """Type-narrow the artifact payload to a resource list."""
    data = artifact.data
    return data if isinstance(data, list) else []


def _first(value: Any) -> Any:
    """HCL blocks are often parsed as single-element lists; unwrap them."""
    if isinstance(value, list) and value:
        return value[0]
    return value


class _TerraformCheck(Check):
    """Base for terraform checks: fixes the target and iterates resources."""

    target = "terraform"

    def run(self, artifact: Artifact) -> Iterator[Finding]:
        for resource in _resources(artifact):
            yield from self.check_resource(resource)

    @abstractmethod
    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        """Yield findings for a single resource."""
        raise NotImplementedError

    def _loc(self, resource: CloudResource) -> Location:
        return Location(path=resource.path, resource=resource.address, line=resource.line)


@register
class S3PublicAcl(_TerraformCheck):
    id = "TF_S3_PUBLIC_ACL"
    title = "S3 bucket grants a public ACL"
    severity = Severity.HIGH

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type not in {"aws_s3_bucket", "aws_s3_bucket_acl"}:
            return
        acl = _first(resource.get("acl"))
        if acl in _aws.PUBLIC_ACLS:
            yield Finding(
                check_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.HIGH,
                location=self._loc(resource),
                description=(
                    f"S3 bucket '{resource.name}' sets acl = \"{acl}\", exposing its "
                    "objects to anonymous or any-AWS-account readers."
                ),
                remediation='Set acl = "private" and use aws_s3_bucket_public_access_block to '
                "block public access at the bucket level.",
                evidence=f'acl = "{acl}"',
                cis_controls=["CIS AWS 2.1.5"],
                mitre_attack=["T1530"],
            )


@register
class S3NoEncryption(_TerraformCheck):
    id = "TF_S3_NO_ENCRYPTION"
    title = "S3 bucket has no server-side encryption configured"
    severity = Severity.MEDIUM

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "aws_s3_bucket":
            return
        # Encryption may be inline (older provider) or a separate resource; we
        # flag the inline-absent case at MEDIUM confidence to avoid false
        # positives when a separate aws_s3_bucket_server_side_encryption_* exists.
        if "server_side_encryption_configuration" not in resource.config:
            yield Finding(
                check_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.MEDIUM,
                location=self._loc(resource),
                description=(
                    f"S3 bucket '{resource.name}' declares no inline "
                    "server_side_encryption_configuration. Data at rest may be unencrypted."
                ),
                remediation="Configure SSE (aws:kms or AES256) via "
                "aws_s3_bucket_server_side_encryption_configuration.",
                cis_controls=["CIS AWS 2.1.1"],
                mitre_attack=["T1530"],
            )


@register
class SecurityGroupWorldIngress(_TerraformCheck):
    id = "TF_SG_WORLD_INGRESS"
    title = "Security group allows ingress from the entire internet"
    severity = Severity.HIGH

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "aws_security_group":
            return
        ingress_blocks = resource.get("ingress") or []
        if isinstance(ingress_blocks, dict):
            ingress_blocks = [ingress_blocks]
        for rule in ingress_blocks:
            if not isinstance(rule, dict):
                continue
            cidrs = rule.get("cidr_blocks") or []
            if not any(c in _aws.WORLD_CIDRS for c in _aws.as_list(cidrs)):
                continue
            from_port = rule.get("from_port")
            port_name = _aws.SENSITIVE_PORTS.get(from_port) if isinstance(from_port, int) else None
            severity = Severity.CRITICAL if port_name else Severity.HIGH
            exposed = f"{port_name} (port {from_port})" if port_name else f"port {from_port}"
            yield Finding(
                check_id=self.id,
                title=self.title,
                severity=severity,
                confidence=Confidence.HIGH,
                location=self._loc(resource),
                description=(
                    f"Security group '{resource.name}' allows ingress to {exposed} "
                    "from 0.0.0.0/0 — reachable by the entire internet."
                ),
                remediation="Restrict cidr_blocks to specific trusted ranges; never expose "
                "administrative ports to 0.0.0.0/0.",
                evidence=f"ingress from_port={from_port} cidr_blocks includes 0.0.0.0/0",
                cis_controls=["CIS AWS 5.2"],
                mitre_attack=["T1190"],  # Exploit Public-Facing Application
            )


@register
class IamWildcardPolicy(_TerraformCheck):
    id = "TF_IAM_WILDCARD"
    title = "IAM policy grants wildcard action or resource"
    severity = Severity.HIGH

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type not in {"aws_iam_policy", "aws_iam_role_policy"}:
            return
        policy = resolve_jsonencode(_first(resource.get("policy")))
        for stmt in _aws.iter_policy_statements(policy):
            kind = _aws.wildcard_kind(stmt)
            if kind is None:
                continue
            action_wild, resource_wild = kind
            critical = action_wild and resource_wild
            yield Finding(
                check_id=self.id,
                title=self.title,
                severity=Severity.CRITICAL if critical else Severity.HIGH,
                confidence=Confidence.HIGH if isinstance(policy, dict) else Confidence.MEDIUM,
                location=self._loc(resource),
                description=(
                    f"IAM policy '{resource.name}' allows "
                    f"Action={'*' if action_wild else _aws.as_list(stmt.get('Action'))} on "
                    f"Resource={'*' if resource_wild else _aws.as_list(stmt.get('Resource'))}. "
                    "Wildcards violate least privilege."
                ),
                remediation="Scope Action and Resource to the minimum the principal needs.",
                cis_controls=["CIS AWS 1.16"],
                mitre_attack=["T1098"],
            )
