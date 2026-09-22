"""Security checks for AWS CloudFormation templates.

Same AWS concepts as the Terraform pack, expressed in CloudFormation's
vocabulary (``AWS::S3::Bucket``, ``SecurityGroupIngress``, ``PolicyDocument``).
Shared logic lives in :mod:`cloudnova.checks._aws`, so "what counts as public"
is defined once for every IaC format.
"""

from __future__ import annotations

from abc import abstractmethod
from collections.abc import Iterator
from typing import ClassVar

from cloudnova.checks import _aws
from cloudnova.core.artifact import Artifact
from cloudnova.core.check import Check, register
from cloudnova.core.findings import Confidence, Finding, Location, Severity
from cloudnova.core.resource import CloudResource


def _resources(artifact: Artifact) -> list[CloudResource]:
    data = artifact.data
    return data if isinstance(data, list) else []


class _CfnCheck(Check):
    """Base for CloudFormation checks: fixes target, iterates resources."""

    target = "cloudformation"

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
class CfnS3PublicAcl(_CfnCheck):
    id = "CFN_S3_PUBLIC_ACL"
    title = "S3 bucket grants a public ACL"
    severity = Severity.HIGH

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "AWS::S3::Bucket":
            return
        acl = resource.get("AccessControl")
        if acl in _aws.PUBLIC_ACLS:
            yield Finding(
                check_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.HIGH,
                location=self._loc(resource),
                description=(
                    f"S3 bucket '{resource.name}' sets AccessControl: {acl}, exposing its "
                    "objects to anonymous or any-AWS-account readers."
                ),
                remediation="Remove AccessControl (default private) and add a "
                "PublicAccessBlockConfiguration that blocks all public access.",
                evidence=f"AccessControl: {acl}",
                cis_controls=["CIS AWS 2.1.5"],
                mitre_attack=["T1530"],
            )


@register
class CfnS3NoEncryption(_CfnCheck):
    id = "CFN_S3_NO_ENCRYPTION"
    title = "S3 bucket has no encryption configured"
    severity = Severity.MEDIUM

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "AWS::S3::Bucket":
            return
        if "BucketEncryption" not in resource.config:
            yield Finding(
                check_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.MEDIUM,
                location=self._loc(resource),
                description=(
                    f"S3 bucket '{resource.name}' declares no BucketEncryption. "
                    "Data at rest may be unencrypted."
                ),
                remediation="Add a BucketEncryption block (aws:kms or AES256).",
                cis_controls=["CIS AWS 2.1.1"],
                mitre_attack=["T1530"],
            )


@register
class CfnSecurityGroupWorldIngress(_CfnCheck):
    id = "CFN_SG_WORLD_INGRESS"
    title = "Security group allows ingress from the entire internet"
    severity = Severity.HIGH

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "AWS::EC2::SecurityGroup":
            return
        for rule in _aws.as_list(resource.get("SecurityGroupIngress")):
            if not isinstance(rule, dict):
                continue
            cidr = rule.get("CidrIp")
            cidr_v6 = rule.get("CidrIpv6")
            if cidr not in _aws.WORLD_CIDRS and cidr_v6 not in _aws.WORLD_CIDRS:
                continue
            from_port = rule.get("FromPort")
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
                remediation="Restrict CidrIp to specific trusted ranges; never expose "
                "administrative ports to the world.",
                evidence=f"SecurityGroupIngress FromPort={from_port} CidrIp=0.0.0.0/0",
                cis_controls=["CIS AWS 5.2"],
                mitre_attack=["T1190"],
            )


@register
class CfnIamWildcard(_CfnCheck):
    id = "CFN_IAM_WILDCARD"
    title = "IAM policy grants wildcard action or resource"
    severity = Severity.HIGH

    _POLICY_TYPES: ClassVar[frozenset[str]] = frozenset(
        {"AWS::IAM::Policy", "AWS::IAM::Role", "AWS::IAM::ManagedPolicy"}
    )

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type not in self._POLICY_TYPES:
            return
        for policy_doc in self._policy_documents(resource):
            for stmt in _aws.iter_policy_statements(policy_doc):
                kind = _aws.wildcard_kind(stmt)
                if kind is None:
                    continue
                action_wild, resource_wild = kind
                critical = action_wild and resource_wild
                yield Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=Severity.CRITICAL if critical else Severity.HIGH,
                    confidence=Confidence.HIGH,
                    location=self._loc(resource),
                    description=(
                        f"IAM resource '{resource.name}' allows "
                        f"Action={'*' if action_wild else _aws.as_list(stmt.get('Action'))} on "
                        f"Resource={'*' if resource_wild else _aws.as_list(stmt.get('Resource'))}. "
                        "Wildcards violate least privilege."
                    ),
                    remediation="Scope Action and Resource to the minimum the principal needs.",
                    cis_controls=["CIS AWS 1.16"],
                    mitre_attack=["T1098"],
                )

    def _policy_documents(self, resource: CloudResource) -> Iterator[dict[str, object]]:
        """Yield every PolicyDocument on a resource.

        ``AWS::IAM::Policy`` has one ``PolicyDocument``; roles carry a list of
        inline ``Policies`` each with its own document.
        """
        doc = resource.get("PolicyDocument")
        if isinstance(doc, dict):
            yield doc
        for inline in _aws.as_list(resource.get("Policies")):
            if isinstance(inline, dict) and isinstance(inline.get("PolicyDocument"), dict):
                yield inline["PolicyDocument"]


@register
class CfnRdsPubliclyAccessible(_CfnCheck):
    id = "CFN_RDS_PUBLIC"
    title = "RDS instance is publicly accessible"
    severity = Severity.HIGH

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "AWS::RDS::DBInstance":
            return
        if resource.get("PubliclyAccessible") is True:
            yield Finding(
                check_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.HIGH,
                location=self._loc(resource),
                description=(
                    f"RDS instance '{resource.name}' sets PubliclyAccessible: true, giving it a "
                    "public endpoint reachable from outside the VPC."
                ),
                remediation="Set PubliclyAccessible: false and reach the database over private "
                "networking.",
                evidence="PubliclyAccessible: true",
                cis_controls=["CIS AWS 2.3.3"],
                mitre_attack=["T1190"],
            )
