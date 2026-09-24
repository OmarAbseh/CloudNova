"""Build a :class:`ResourceGraph` from normalized IaC resources.

Terraform and CloudFormation are handled by parallel sections that share the
same node/edge/role vocabulary; each has its own reference-extraction and
role-tagging because the dialects differ (HCL ``${type.name}`` interpolations
vs. CloudFormation ``Ref``/``Fn::GetAtt`` logical IDs).

Two jobs:

1. **Edges** — Terraform interpolations (``${aws_iam_role.r.name}``) encode the
   relationships between resources. We extract every ``type.name`` reference from
   a resource's config and classify the edge by the attribute it appeared under
   (a ``role =`` reference is CAN_ASSUME/GRANTS, a security-group reference is
   PROTECTED_BY, etc.).
2. **Roles** — we tag each node with security roles (internet-exposed, privileged,
   data-store, compute) derived from its own configuration. Attack-path search
   then only needs the graph, not the raw resources.

Terraform is the first supported format because its references are explicit and
resolvable; the same graph shape will later be populated from live cloud data.
"""

from __future__ import annotations

import re

from cloudnova.checks import _aws
from cloudnova.core.parsers.terraform import resolve_jsonencode
from cloudnova.core.resource import CloudResource, IaCFormat
from cloudnova.graph.model import EdgeKind, NodeRole, ResourceGraph

# Matches a Terraform resource reference like ``aws_iam_role.my_role`` inside an
# interpolation. We capture ``type.name`` and ignore the trailing attribute.
_REF_RE = re.compile(r"\b(aws_[a-z0-9_]+)\.([A-Za-z0-9_-]+)")

_COMPUTE_TYPES = {"aws_instance", "aws_lambda_function", "aws_ecs_task_definition"}
_DATA_TYPES = {"aws_s3_bucket", "aws_db_instance", "aws_dynamodb_table", "aws_rds_cluster"}
_ROLE_TYPES = {"aws_iam_role", "aws_iam_instance_profile"}

# Config attribute name -> the edge kind a reference under it implies.
_ATTR_EDGE_KINDS: dict[str, EdgeKind] = {
    "iam_instance_profile": EdgeKind.CAN_ASSUME,
    "role": EdgeKind.CAN_ASSUME,
    "roles": EdgeKind.CAN_ASSUME,
    "vpc_security_group_ids": EdgeKind.PROTECTED_BY,
    "security_groups": EdgeKind.PROTECTED_BY,
}


def _iter_references(value: object) -> list[str]:
    """Collect every ``type.name`` reference in a config value (recursively)."""
    refs: list[str] = []
    if isinstance(value, str):
        refs += [f"{m.group(1)}.{m.group(2)}" for m in _REF_RE.finditer(value)]
    elif isinstance(value, list):
        for item in value:
            refs += _iter_references(item)
    elif isinstance(value, dict):
        for item in value.values():
            refs += _iter_references(item)
    return refs


def _has_wildcard_policy(resource: CloudResource) -> bool:
    policy = resolve_jsonencode(resource.get("policy"))
    if isinstance(policy, list) and policy:
        policy = policy[0]
    return any(_aws.wildcard_kind(stmt) for stmt in _aws.iter_policy_statements(policy))


def _has_world_ingress(resource: CloudResource) -> bool:
    ingress = resource.get("ingress") or []
    if isinstance(ingress, dict):
        ingress = [ingress]
    for rule in ingress:
        if not isinstance(rule, dict):
            continue
        if any(c in _aws.WORLD_CIDRS for c in _aws.as_list(rule.get("cidr_blocks"))):
            return True
    return False


def _tag_terraform_roles(graph: ResourceGraph, node_ids: set[str]) -> None:
    """Assign security roles to Terraform nodes based on their configuration."""
    world_open_sgs = {
        i
        for i in node_ids
        if (n := graph.node(i))
        and n.type == "aws_security_group"
        and _has_world_ingress(n.resource)
    }
    privileged_ids = {
        i
        for i in node_ids
        if (n := graph.node(i))
        and n.type in {"aws_iam_policy", "aws_iam_role_policy"}
        and _has_wildcard_policy(n.resource)
    }
    for node_id in node_ids:
        node = graph.node(node_id)
        if node is None:
            continue
        if node.type in _COMPUTE_TYPES:
            node.roles.add(NodeRole.COMPUTE)
            # A compute node protected by a world-open security group is exposed.
            for edge in graph.edges_from(node.id):
                if edge.kind is EdgeKind.PROTECTED_BY and edge.dst in world_open_sgs:
                    node.roles.add(NodeRole.INTERNET_EXPOSED)
        if node.type in _DATA_TYPES:
            node.roles.add(NodeRole.DATA_STORE)
        # A role/profile that grants a wildcard policy is privileged. We tag the
        # identity (role/profile), not the policy document itself, because the
        # identity is what an attacker actually gains — reporting both would be
        # redundant noise.
        if node.type in _ROLE_TYPES:
            for edge in graph.edges_from(node.id):
                if edge.kind is EdgeKind.GRANTS and edge.dst in privileged_ids:
                    node.roles.add(NodeRole.PRIVILEGED)


def _edge_kind_for(attr: str, dst_type: str) -> EdgeKind:
    if attr in _ATTR_EDGE_KINDS:
        return _ATTR_EDGE_KINDS[attr]
    # An IAM role/profile referencing a policy grants those permissions.
    if dst_type in {"aws_iam_policy", "aws_iam_role_policy"}:
        return EdgeKind.GRANTS
    if dst_type in _ROLE_TYPES:
        return EdgeKind.CAN_ASSUME
    return EdgeKind.REFERENCES


def _build_terraform(graph: ResourceGraph, tf_resources: list[CloudResource]) -> None:
    for resource in tf_resources:
        graph.add_node(resource)
    types_by_address = {r.address: r.type for r in tf_resources}
    for resource in tf_resources:
        for attr, value in resource.config.items():
            for ref in _iter_references(value):
                if ref == resource.address or ref not in types_by_address:
                    continue
                graph.add_edge(resource.address, ref, _edge_kind_for(attr, types_by_address[ref]))
        # An inline role policy points role->policy, but the reference lives on
        # the policy (its `role =`). Add the reverse GRANTS edge so the role
        # node owns the grant.
        if resource.type == "aws_iam_role_policy":
            for ref in _iter_references(resource.get("role")):
                if ref in types_by_address:
                    graph.add_edge(ref, resource.address, EdgeKind.GRANTS)
    _tag_terraform_roles(graph, {r.address for r in tf_resources})


def build_graph(resources: list[CloudResource]) -> ResourceGraph:
    """Construct a resource graph from IaC resources (Terraform + CloudFormation).

    Each format's nodes and edges are built independently into the same graph.
    Because there are no cross-format references, attack-path search naturally
    never crosses formats, so the two can safely share one graph object.
    """
    graph = ResourceGraph()
    _build_terraform(graph, [r for r in resources if r.format is IaCFormat.TERRAFORM])
    _build_cloudformation(graph, [r for r in resources if r.format is IaCFormat.CLOUDFORMATION])
    _add_data_access_edges(graph)
    return graph


def _add_data_access_edges(graph: ResourceGraph) -> None:
    """Connect wildcard-admin identities to the data stores they can reach.

    A role with ``Action:"*"`` can read every data store in its account, so we
    add a CAN_ACCESS edge from each privileged node to each data store of the
    same IaC format (stacks don't share resources across formats). This is what
    lets attack-path search report data *exfiltration*, not just privilege
    escalation — the wildcard grant, not an explicit reference, is the link.
    """
    privileged = [n for n in graph.nodes() if n.has(NodeRole.PRIVILEGED)]
    data_stores = [n for n in graph.nodes() if n.has(NodeRole.DATA_STORE)]
    for role in privileged:
        for store in data_stores:
            if role.resource.format is store.resource.format:
                graph.add_edge(role.id, store.id, EdgeKind.CAN_ACCESS)


# --- CloudFormation -------------------------------------------------------

_CFN_COMPUTE_TYPES = {"AWS::EC2::Instance", "AWS::Lambda::Function", "AWS::ECS::TaskDefinition"}
_CFN_DATA_TYPES = {
    "AWS::S3::Bucket",
    "AWS::RDS::DBInstance",
    "AWS::DynamoDB::Table",
    "AWS::RDS::DBCluster",
}
_CFN_ROLE_TYPES = {"AWS::IAM::Role", "AWS::IAM::InstanceProfile"}
_CFN_POLICY_TYPES = {"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"}

# CloudFormation property name -> edge kind for a reference under it.
_CFN_ATTR_EDGE_KINDS: dict[str, EdgeKind] = {
    "IamInstanceProfile": EdgeKind.CAN_ASSUME,
    "Roles": EdgeKind.CAN_ASSUME,
    "SecurityGroupIds": EdgeKind.PROTECTED_BY,
    "SecurityGroups": EdgeKind.PROTECTED_BY,
    "VpcSecurityGroupIds": EdgeKind.PROTECTED_BY,
    "ManagedPolicyArns": EdgeKind.GRANTS,
}


def _cfn_references(value: object) -> list[str]:
    """Collect logical IDs referenced via ``Ref`` / ``Fn::GetAtt`` (recursively)."""
    refs: list[str] = []
    if isinstance(value, dict):
        for key, inner in value.items():
            if key == "Ref" and isinstance(inner, str):
                refs.append(inner)
            elif key == "Fn::GetAtt":
                if isinstance(inner, str):
                    refs.append(inner.split(".")[0])
                elif isinstance(inner, list) and inner:
                    refs.append(str(inner[0]))
            else:
                refs += _cfn_references(inner)
    elif isinstance(value, list):
        for item in value:
            refs += _cfn_references(item)
    return refs


def _cfn_has_world_ingress(resource: CloudResource) -> bool:
    for rule in _aws.as_list(resource.get("SecurityGroupIngress")):
        if not isinstance(rule, dict):
            continue
        if rule.get("CidrIp") in _aws.WORLD_CIDRS or rule.get("CidrIpv6") in _aws.WORLD_CIDRS:
            return True
    return False


def _cfn_role_has_wildcard(resource: CloudResource) -> bool:
    """A role/policy is privileged if any of its policy documents has a wildcard."""
    docs: list[object] = []
    doc = resource.get("PolicyDocument")
    if isinstance(doc, dict):
        docs.append(doc)
    for inline in _aws.as_list(resource.get("Policies")):
        if isinstance(inline, dict) and isinstance(inline.get("PolicyDocument"), dict):
            docs.append(inline["PolicyDocument"])
    return any(_aws.wildcard_kind(s) for d in docs for s in _aws.iter_policy_statements(d))


def _cfn_edge_kind_for(attr: str, dst_type: str) -> EdgeKind:
    if attr in _CFN_ATTR_EDGE_KINDS:
        return _CFN_ATTR_EDGE_KINDS[attr]
    if dst_type in _CFN_POLICY_TYPES:
        return EdgeKind.GRANTS
    if dst_type in _CFN_ROLE_TYPES:
        return EdgeKind.CAN_ASSUME
    return EdgeKind.REFERENCES


def _build_cloudformation(graph: ResourceGraph, cfn_resources: list[CloudResource]) -> None:
    for resource in cfn_resources:
        graph.add_node(resource)
    # CloudFormation references use logical IDs (the resource name), so map those
    # back to the graph node addresses (type.logical_id).
    by_logical = {r.name: r for r in cfn_resources}
    for resource in cfn_resources:
        for attr, value in resource.config.items():
            for logical in _cfn_references(value):
                target = by_logical.get(logical)
                if target is None or target.address == resource.address:
                    continue
                graph.add_edge(
                    resource.address, target.address, _cfn_edge_kind_for(attr, target.type)
                )
    _tag_cloudformation_roles(graph, {r.address for r in cfn_resources})


def _tag_cloudformation_roles(graph: ResourceGraph, node_ids: set[str]) -> None:
    world_open_sgs = {
        i
        for i in node_ids
        if (n := graph.node(i))
        and n.type == "AWS::EC2::SecurityGroup"
        and _cfn_has_world_ingress(n.resource)
    }
    for node_id in node_ids:
        node = graph.node(node_id)
        if node is None:
            continue
        if node.type in _CFN_COMPUTE_TYPES:
            node.roles.add(NodeRole.COMPUTE)
            for edge in graph.edges_from(node.id):
                if edge.kind is EdgeKind.PROTECTED_BY and edge.dst in world_open_sgs:
                    node.roles.add(NodeRole.INTERNET_EXPOSED)
        if node.type in _CFN_DATA_TYPES:
            node.roles.add(NodeRole.DATA_STORE)
        # A role is privileged if it carries an inline wildcard policy, or grants
        # a policy node that does.
        if node.type in _CFN_ROLE_TYPES:
            if _cfn_role_has_wildcard(node.resource):
                node.roles.add(NodeRole.PRIVILEGED)
            for edge in graph.edges_from(node.id):
                dst = graph.node(edge.dst)
                if (
                    edge.kind is EdgeKind.GRANTS
                    and dst is not None
                    and dst.type in _CFN_POLICY_TYPES
                    and _cfn_role_has_wildcard(dst.resource)
                ):
                    node.roles.add(NodeRole.PRIVILEGED)
