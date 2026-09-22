"""Build a :class:`ResourceGraph` from normalized Terraform resources.

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


def _tag_roles(graph: ResourceGraph) -> None:
    """Assign security roles to nodes based on their own configuration."""
    world_open_sgs = {
        n.id
        for n in graph.nodes()
        if n.type == "aws_security_group" and _has_world_ingress(n.resource)
    }
    privileged_ids = {
        n.id
        for n in graph.nodes()
        if n.type in {"aws_iam_policy", "aws_iam_role_policy"} and _has_wildcard_policy(n.resource)
    }
    for node in graph.nodes():
        if node.type in _COMPUTE_TYPES:
            node.roles.add(NodeRole.COMPUTE)
        if node.type in _DATA_TYPES:
            node.roles.add(NodeRole.DATA_STORE)
        # A compute node protected by a world-open security group is exposed.
        if node.type in _COMPUTE_TYPES:
            for edge in graph.edges_from(node.id):
                if edge.kind is EdgeKind.PROTECTED_BY and edge.dst in world_open_sgs:
                    node.roles.add(NodeRole.INTERNET_EXPOSED)
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


def build_graph(resources: list[CloudResource]) -> ResourceGraph:
    """Construct a resource graph from Terraform resources."""
    graph = ResourceGraph()
    tf_resources = [r for r in resources if r.format is IaCFormat.TERRAFORM]
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

    _tag_roles(graph)
    return graph
