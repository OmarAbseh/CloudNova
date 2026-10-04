"""Terraform rules for network exposure and transport security.

Everything here is about whether something can be reached, and whether what
crosses the wire can be read. Exposure is the first half of every attack path,
so these rules are what turn a list of misconfigurations into a chain.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from cloudnova.checks._tf_base import (
    WORLD_CIDRS,
    AttributeCheck,
    TerraformCheck,
    first,
    missing,
    resources,
    truthy,
)
from cloudnova.core.artifact import Artifact
from cloudnova.core.check import register
from cloudnova.core.findings import Confidence, Finding, Severity
from cloudnova.core.resource import CloudResource

# Ports where exposure to the internet is almost always a mistake rather than a
# design choice. Web ports are deliberately absent: 80 and 443 open to the
# world is what a web server is for.
SENSITIVE_PORTS: dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    2375: "Docker API (unauthenticated)",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5984: "CouchDB",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

# TLS policies that still permit TLS 1.0 or 1.1.
WEAK_TLS_POLICIES = frozenset(
    {
        "ELBSecurityPolicy-2016-08",
        "ELBSecurityPolicy-TLS-1-0-2015-04",
        "ELBSecurityPolicy-TLS-1-1-2017-01",
        "ELBSecurityPolicy-FS-2018-06",
    }
)


def _as_int(value: Any) -> int | None:
    try:
        return int(first(value))
    except (TypeError, ValueError):
        return None


@register
class SecurityGroupSensitivePort(TerraformCheck):
    """World-open ingress on a port that should never face the internet.

    Distinct from the existing broad world-ingress rule: naming the service
    turns "this is open" into "your database is on the internet", which is the
    difference between a finding that gets triaged and one that gets ignored.
    """

    id = "TF_SG_SENSITIVE_PORT_WORLD"
    title = "Security group exposes a sensitive service to the internet"
    severity = Severity.CRITICAL

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type not in {"aws_security_group", "aws_security_group_rule"}:
            return
        for rule in self._ingress_rules(resource):
            cidrs = rule.get("cidr_blocks") or []
            if isinstance(cidrs, str):
                cidrs = [cidrs]
            if not isinstance(cidrs, list):
                continue
            if not any(str(c) in WORLD_CIDRS for c in cidrs):
                continue
            lo, hi = _as_int(rule.get("from_port")), _as_int(rule.get("to_port"))
            if lo is None or hi is None:
                continue
            for port, service in SENSITIVE_PORTS.items():
                if lo <= port <= hi:
                    yield Finding(
                        check_id=self.id,
                        title=self.title,
                        severity=self.severity,
                        confidence=Confidence.HIGH,
                        location=self.loc(resource),
                        description=(
                            f"Security group '{resource.name}' allows the whole internet "
                            f"to reach port {port} ({service}). This is directly "
                            "scannable and is how estates get breached without an "
                            "application bug being involved."
                        ),
                        remediation=(
                            f"Restrict the {service} rule to known CIDRs, or front it "
                            "with a bastion or SSM Session Manager."
                        ),
                        evidence=f"ingress {lo}-{hi} from 0.0.0.0/0 covers {port}/{service}",
                        cis_controls=["CIS AWS 5.2"],
                        mitre_attack=["T1190", "T1133"],
                    )

    def _ingress_rules(self, resource: CloudResource) -> list[dict[str, Any]]:
        if resource.type == "aws_security_group_rule":
            if str(first(resource.get("type")) or "").lower() != "ingress":
                return []
            return [dict(resource.config)]
        raw = resource.get("ingress")
        if isinstance(raw, dict):
            return [raw]
        if isinstance(raw, list):
            return [r for r in raw if isinstance(r, dict)]
        return []


@register
class LoadBalancerNoHttps(TerraformCheck):
    id = "TF_LB_PLAINTEXT_LISTENER"
    title = "Load balancer listener accepts plaintext HTTP"
    severity = Severity.MEDIUM

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "aws_lb_listener":
            return
        protocol = str(first(resource.get("protocol")) or "").upper()
        if protocol not in {"HTTP", "TCP"}:
            return
        # A plain HTTP listener that only redirects to HTTPS is the correct
        # pattern, not a finding.
        action = first(resource.get("default_action"))
        if isinstance(action, dict) and str(first(action.get("type")) or "") == "redirect":
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.MEDIUM,
            location=self.loc(resource),
            description=(
                f"Listener '{resource.name}' serves {protocol}, so credentials and "
                "session cookies cross the network in cleartext and can be read or "
                "modified in transit."
            ),
            remediation=(
                "Use HTTPS or TLS with an ACM certificate, and make any HTTP listener "
                "redirect rather than serve."
            ),
            evidence=f'protocol = "{protocol}"',
            cis_controls=[],
            mitre_attack=["T1040", "T1557"],
        )


@register
class LoadBalancerWeakTls(TerraformCheck):
    id = "TF_LB_WEAK_TLS_POLICY"
    title = "Load balancer allows obsolete TLS versions"
    severity = Severity.MEDIUM

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "aws_lb_listener":
            return
        policy = str(first(resource.get("ssl_policy")) or "")
        if policy not in WEAK_TLS_POLICIES:
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Listener '{resource.name}' uses {policy}, which still negotiates "
                "TLS 1.0 or 1.1. Both are deprecated and fail PCI DSS."
            ),
            remediation="Use ELBSecurityPolicy-TLS13-1-2-2021-06 or later.",
            evidence=f'ssl_policy = "{policy}"',
            cis_controls=[],
            mitre_attack=["T1040"],
        )


@register
class LoadBalancerNoLogs(TerraformCheck):
    id = "TF_LB_NO_ACCESS_LOGS"
    title = "Load balancer has access logging disabled"
    severity = Severity.LOW

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type not in {"aws_lb", "aws_alb", "aws_elb"}:
            return
        block = first(resource.get("access_logs"))
        if isinstance(block, dict) and truthy(block.get("enabled")):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.MEDIUM,
            location=self.loc(resource),
            description=(
                f"Load balancer '{resource.name}' keeps no access logs, so there is no "
                "record of who reached the application. An incident becomes "
                "unreconstructable."
            ),
            remediation="Add an access_logs block with enabled = true and an S3 bucket.",
            evidence="access_logs absent or disabled",
            cis_controls=[],
            mitre_attack=["T1562"],
        )


@register
class VpcNoFlowLogs(TerraformCheck):
    """A VPC with no accompanying flow log resource anywhere in the module.

    Unlike the attribute rules, this one is about something missing from the
    whole file rather than wrong on one resource, so it reports once per VPC
    and at medium confidence: the flow log may legitimately live elsewhere.
    """

    id = "TF_VPC_NO_FLOW_LOGS"
    title = "VPC has no flow logs"
    severity = Severity.MEDIUM

    def run(self, artifact: Artifact) -> Iterator[Finding]:
        found = resources(artifact)
        vpcs = [r for r in found if r.type == "aws_vpc"]
        has_flow_log = any(r.type == "aws_flow_log" for r in found)
        if has_flow_log:
            return
        for vpc in vpcs:
            yield Finding(
                check_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.MEDIUM,
                location=self.loc(vpc),
                description=(
                    f"VPC '{vpc.name}' has no aws_flow_log in this configuration. "
                    "Without flow logs there is no network-level evidence of "
                    "lateral movement or exfiltration."
                ),
                remediation=(
                    'Add an aws_flow_log for the VPC with traffic_type = "ALL", '
                    "shipping to CloudWatch Logs or S3."
                ),
                evidence="no aws_flow_log resource found alongside this VPC",
                cis_controls=["CIS AWS 3.9"],
                mitre_attack=["T1562.008"],
            )

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        return iter(())


@register
class ApiGatewayNoLogging(TerraformCheck):
    id = "TF_APIGW_NO_LOGGING"
    title = "API Gateway stage has no execution logging"
    severity = Severity.LOW

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type not in {"aws_api_gateway_stage", "aws_apigatewayv2_stage"}:
            return
        if not missing(resource.get("access_log_settings")):
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.MEDIUM,
            location=self.loc(resource),
            description=(
                f"API stage '{resource.name}' logs nothing, so abuse of the API leaves "
                "no trace and rate-limit tuning has no data behind it."
            ),
            remediation="Add an access_log_settings block pointing at a log group.",
            evidence="access_log_settings absent",
            cis_controls=[],
            mitre_attack=["T1562"],
        )


@register
class CloudFrontNoHttpsOnly(TerraformCheck):
    id = "TF_CLOUDFRONT_ALLOWS_HTTP"
    title = "CloudFront distribution serves plaintext HTTP"
    severity = Severity.MEDIUM

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type != "aws_cloudfront_distribution":
            return
        behaviour = first(resource.get("default_cache_behavior"))
        if not isinstance(behaviour, dict):
            return
        policy = str(first(behaviour.get("viewer_protocol_policy")) or "").lower()
        if policy in {"redirect-to-https", "https-only"}:
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=(
                f"Distribution '{resource.name}' has viewer_protocol_policy = "
                f'"{policy or "unset"}", so visitors can be served over plaintext '
                "and downgraded."
            ),
            remediation='Set viewer_protocol_policy = "redirect-to-https".',
            evidence=f'viewer_protocol_policy = "{policy or "unset"}"',
            cis_controls=[],
            mitre_attack=["T1040", "T1557"],
        )


@register
class ElasticsearchPublic(AttributeCheck):
    id = "TF_OPENSEARCH_PUBLIC"
    title = "OpenSearch domain is not inside a VPC"
    severity = Severity.HIGH
    types = frozenset({"aws_elasticsearch_domain", "aws_opensearch_domain"})
    attribute = "vpc_options"
    description_template = (
        "Search domain '{name}' has no vpc_options, so it has a public endpoint. "
        "Open search clusters are a well-known source of bulk data exposure."
    )
    remediation_text = "Add a vpc_options block to place the domain in private subnets."
    cis = ()
    mitre = ("T1530",)
