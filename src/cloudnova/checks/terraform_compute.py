"""Terraform rules for compute, containers and identity.

These are the rules about what a workload can do once it is running, and what
an attacker inherits by landing on it. Together with the network pack they are
the two halves of an attack path: reach, then privilege.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import ClassVar

from cloudnova.checks._tf_base import AttributeCheck, TerraformCheck, first, missing, truthy
from cloudnova.core.check import register
from cloudnova.core.findings import Confidence, Finding, Severity
from cloudnova.core.parsers.terraform import resolve_jsonencode
from cloudnova.core.resource import CloudResource

# Managed policies that hand over the account, or close to it.
DANGEROUS_MANAGED_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess": "full administrator",
    "arn:aws:iam::aws:policy/PowerUserAccess": "power user",
    "arn:aws:iam::aws:policy/IAMFullAccess": "full IAM control",
}


@register
class LambdaNoEnvEncryption(TerraformCheck):
    id = "TF_LAMBDA_ENV_NOT_ENCRYPTED"
    title = "Lambda environment variables are not encrypted with a CMK"
    severity = Severity.MEDIUM

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "aws_lambda_function":
            return
        env = first(resource.get("environment"))
        if not isinstance(env, dict) or missing(env.get("variables")):
            return
        if not missing(resource.get("kms_key_arn")):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.MEDIUM,
            location=self.loc(resource),
            description=(
                f"Function '{resource.name}' carries environment variables with no "
                "kms_key_arn, so anyone with lambda:GetFunction can read them. This "
                "is where connection strings and API keys usually live."
            ),
            remediation=(
                "Set kms_key_arn to a key you control, or move the values into "
                "Secrets Manager and read them at runtime."
            ),
            evidence="environment.variables set without kms_key_arn",
            cis_controls=[],
            mitre_attack=["T1552.001"],
        )


@register
class LambdaPublicInvoke(TerraformCheck):
    id = "TF_LAMBDA_PUBLIC_INVOKE"
    title = "Lambda function can be invoked by anyone"
    severity = Severity.CRITICAL

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "aws_lambda_permission":
            return
        principal = str(first(resource.get("principal")) or "")
        if principal != "*":
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Permission '{resource.name}' grants principal = \"*\", so any AWS "
                "principal on earth can invoke the function and whatever its "
                "execution role can reach."
            ),
            remediation=(
                "Name the invoking service or account explicitly, and set "
                "source_arn to scope it further."
            ),
            evidence='principal = "*"',
            cis_controls=[],
            mitre_attack=["T1190"],
        )


@register
class IamDangerousManagedPolicy(TerraformCheck):
    id = "TF_IAM_ADMIN_POLICY_ATTACHED"
    title = "An AWS-managed administrator policy is attached"
    severity = Severity.HIGH

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type not in {
            "aws_iam_role_policy_attachment",
            "aws_iam_user_policy_attachment",
            "aws_iam_group_policy_attachment",
            "aws_iam_policy_attachment",
        }:
            return
        arn = str(first(resource.get("policy_arn")) or "")
        label = DANGEROUS_MANAGED_POLICIES.get(arn)
        if label is None:
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Attachment '{resource.name}' grants {label}. Anything that "
                "compromises this identity compromises the account, which is what "
                "turns a single exposed workload into a full estate breach."
            ),
            remediation=(
                "Replace it with a least-privilege policy listing only the actions "
                "and resources actually used."
            ),
            evidence=f"policy_arn = {arn}",
            cis_controls=["CIS AWS 1.16"],
            mitre_attack=["T1078.004", "T1098"],
        )


@register
class IamUserAccessKey(TerraformCheck):
    id = "TF_IAM_STATIC_ACCESS_KEY"
    title = "A long-lived IAM access key is declared in code"
    severity = Severity.HIGH

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "aws_iam_access_key":
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.MEDIUM,
            location=self.loc(resource),
            description=(
                f"Access key '{resource.name}' is a static, long-lived credential. "
                "Keys like this leak into git, CI logs and laptops, and they do not "
                "expire on their own."
            ),
            remediation=(
                "Use an IAM role with a trust policy instead: OIDC for CI, instance "
                "profiles for EC2, IRSA for EKS. Reserve static keys for systems that "
                "genuinely cannot assume a role."
            ),
            evidence="aws_iam_access_key declared",
            cis_controls=["CIS AWS 1.14"],
            mitre_attack=["T1552.001"],
        )


@register
class EksPublicEndpoint(TerraformCheck):
    id = "TF_EKS_PUBLIC_ENDPOINT"
    title = "EKS control plane endpoint is public"
    severity = Severity.HIGH

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "aws_eks_cluster":
            return
        vpc = first(resource.get("vpc_config"))
        if not isinstance(vpc, dict):
            return
        public = vpc.get("endpoint_public_access")
        # The attribute defaults to true in the AWS provider, so absence is
        # also exposure.
        if public is not None and not truthy(public):
            return
        cidrs = vpc.get("public_access_cidrs")
        if (
            isinstance(cidrs, list)
            and cidrs
            and not any(str(first(c)) in {"0.0.0.0/0", "::/0"} for c in cidrs)
        ):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.MEDIUM,
            location=self.loc(resource),
            description=(
                f"Cluster '{resource.name}' exposes its Kubernetes API to the "
                "internet. The API server is the control plane for every workload "
                "in the cluster."
            ),
            remediation=(
                "Set endpoint_public_access = false, or restrict public_access_cidrs "
                "to your office and CI ranges."
            ),
            evidence="endpoint_public_access not disabled and no CIDR restriction",
            cis_controls=[],
            mitre_attack=["T1190"],
        )


@register
class EksNoSecretEncryption(TerraformCheck):
    id = "TF_EKS_NO_SECRET_ENCRYPTION"
    title = "EKS cluster does not encrypt Kubernetes secrets with a KMS key"
    severity = Severity.MEDIUM

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "aws_eks_cluster":
            return
        if not missing(resource.get("encryption_config")):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Cluster '{resource.name}' has no encryption_config, so Kubernetes "
                "secrets sit in etcd protected only by disk encryption. Envelope "
                "encryption is what separates etcd access from secret access."
            ),
            remediation=('Add encryption_config with resources = ["secrets"] and a KMS key.'),
            evidence="encryption_config absent",
            cis_controls=[],
            mitre_attack=["T1552.007"],
        )


@register
class EksNoLogging(TerraformCheck):
    id = "TF_EKS_NO_AUDIT_LOGGING"
    title = "EKS control plane audit logging is incomplete"
    severity = Severity.LOW

    _WANTED: ClassVar[frozenset[str]] = frozenset({"api", "audit", "authenticator"})

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "aws_eks_cluster":
            return
        raw = resource.get("enabled_cluster_log_types")
        enabled = {str(x).lower() for x in raw} if isinstance(raw, list) else set()
        gaps = self._WANTED - enabled
        if not gaps:
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Cluster '{resource.name}' does not ship {', '.join(sorted(gaps))} "
                "logs. Without the audit log there is no record of what was created "
                "or who created it inside the cluster."
            ),
            remediation=(
                'Set enabled_cluster_log_types = ["api", "audit", "authenticator", '
                '"controllerManager", "scheduler"].'
            ),
            evidence=f"missing log types: {', '.join(sorted(gaps))}",
            cis_controls=[],
            mitre_attack=["T1562.008"],
        )


@register
class EcrMutableTags(TerraformCheck):
    id = "TF_ECR_MUTABLE_TAGS"
    title = "ECR repository allows mutable image tags"
    severity = Severity.MEDIUM

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "aws_ecr_repository":
            return
        mutability = str(first(resource.get("image_tag_mutability")) or "MUTABLE").upper()
        if mutability == "IMMUTABLE":
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Repository '{resource.name}' allows tags to be overwritten, so the "
                "image behind a deployed tag can be swapped after review. This is a "
                "supply-chain weakness, not a hygiene issue."
            ),
            remediation='Set image_tag_mutability = "IMMUTABLE" and deploy by digest.',
            evidence=f'image_tag_mutability = "{mutability}"',
            cis_controls=[],
            mitre_attack=["T1525"],
        )


@register
class EcrNoScanOnPush(TerraformCheck):
    id = "TF_ECR_NO_SCAN_ON_PUSH"
    title = "ECR repository does not scan images on push"
    severity = Severity.LOW

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "aws_ecr_repository":
            return
        block = first(resource.get("image_scanning_configuration"))
        if isinstance(block, dict) and truthy(block.get("scan_on_push")):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Repository '{resource.name}' does not scan on push, so a known-"
                "vulnerable base image reaches production without anything "
                "objecting."
            ),
            remediation="Add image_scanning_configuration { scan_on_push = true }.",
            evidence="scan_on_push not enabled",
            cis_controls=[],
            mitre_attack=["T1190"],
        )


@register
class EbsNotEncryptedByDefault(AttributeCheck):
    id = "TF_EBS_DEFAULT_ENCRYPTION_OFF"
    title = "Account-level EBS encryption by default is disabled"
    severity = Severity.MEDIUM
    types = frozenset({"aws_ebs_encryption_by_default"})
    attribute = "enabled"
    description_template = (
        "Default EBS encryption is turned off, so every future volume that forgets "
        "to ask for encryption will be unencrypted."
    )
    remediation_text = "Set enabled = true so encryption is the default, not a choice."
    cis = ("CIS AWS 2.2.1",)
    mitre = ("T1530",)


@register
class EcsTaskHostNetwork(TerraformCheck):
    id = "TF_ECS_HOST_NETWORK"
    title = "ECS task definition uses host networking"
    severity = Severity.MEDIUM

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "aws_ecs_task_definition":
            return
        mode = str(first(resource.get("network_mode")) or "").lower()
        if mode != "host":
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Task '{resource.name}' shares the host network namespace, so the "
                "container can reach the instance metadata service and every port "
                "bound on the host."
            ),
            remediation='Use network_mode = "awsvpc" to give the task its own ENI.',
            evidence='network_mode = "host"',
            cis_controls=[],
            mitre_attack=["T1611"],
        )


@register
class IamPassRoleWildcard(TerraformCheck):
    """iam:PassRole on "*" is the classic privilege-escalation primitive.

    Separate from the broad wildcard rule because this specific pair is how an
    attacker with limited permissions attaches an admin role to a resource they
    control and inherits it.
    """

    id = "TF_IAM_PASSROLE_WILDCARD"
    title = "Policy allows iam:PassRole on any role"
    severity = Severity.CRITICAL

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type not in {"aws_iam_policy", "aws_iam_role_policy"}:
            return
        doc = resolve_jsonencode(resource.get("policy"))
        if not isinstance(doc, dict):
            return
        statements = doc.get("Statement")
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list):
            return
        for statement in statements:
            if not isinstance(statement, dict):
                continue
            if str(statement.get("Effect", "")).lower() != "allow":
                continue
            actions = statement.get("Action")
            actions = [actions] if isinstance(actions, str) else actions
            if not isinstance(actions, list):
                continue
            if not any(str(a).lower() in {"iam:passrole", "iam:*", "*"} for a in actions):
                continue
            resources_ = statement.get("Resource")
            resources_ = [resources_] if isinstance(resources_, str) else resources_
            if not isinstance(resources_, list) or "*" not in [str(r) for r in resources_]:
                continue
            yield Finding(
                check_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.HIGH,
                location=self.loc(resource),
                description=(
                    f"Policy '{resource.name}' allows iam:PassRole on every role. A "
                    "holder can attach an administrator role to a Lambda, EC2 "
                    "instance or task they control and inherit it. This is one of "
                    "the most reliable privilege-escalation paths in AWS."
                ),
                remediation=(
                    "Scope Resource to the specific role ARNs that may be passed, and "
                    "add an iam:PassedToService condition."
                ),
                evidence='Allow iam:PassRole on Resource "*"',
                cis_controls=["CIS AWS 1.16"],
                mitre_attack=["T1548", "T1098"],
            )
