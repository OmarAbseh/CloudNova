"""The resource graph: nodes are cloud resources, edges are relationships.

Kept deliberately small and dependency-free (no networkx) so it's easy to reason
about and test. A node wraps a :class:`CloudResource` and carries a set of
security *roles* (exposed, privileged, data-store …) that the builder tags on;
attack-path search then reduces to a walk from an exposed node to a sensitive
one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from cloudnova.core.resource import CloudResource


class EdgeKind(StrEnum):
    """The relationship an edge represents (src → dst)."""

    #: src is protected/attached to dst (instance → security group).
    PROTECTED_BY = "protected_by"
    #: src can assume or use the identity dst (instance → instance profile → role).
    CAN_ASSUME = "can_assume"
    #: src grants the permissions in dst (role → policy).
    GRANTS = "grants"
    #: generic reference between resources we could not classify further.
    REFERENCES = "references"


class NodeRole(StrEnum):
    """Security-relevant roles a node can play in an attack path."""

    #: Reachable from the internet (e.g. behind a world-open security group).
    INTERNET_EXPOSED = "internet_exposed"
    #: Carries excessive permissions (e.g. a wildcard IAM policy).
    PRIVILEGED = "privileged"
    #: Holds or fronts sensitive data (S3, RDS, …).
    DATA_STORE = "data_store"
    #: A compute identity that can act (EC2, Lambda, …).
    COMPUTE = "compute"


@dataclass
class Node:
    """A vertex in the resource graph."""

    id: str
    resource: CloudResource
    roles: set[NodeRole] = field(default_factory=set)

    @property
    def type(self) -> str:
        return self.resource.type

    def has(self, role: NodeRole) -> bool:
        return role in self.roles


@dataclass(frozen=True)
class Edge:
    """A directed relationship between two nodes."""

    src: str
    dst: str
    kind: EdgeKind


class ResourceGraph:
    """A tiny directed multigraph of cloud resources."""

    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._out: dict[str, list[Edge]] = {}

    def add_node(self, resource: CloudResource) -> Node:
        node = self._nodes.get(resource.address)
        if node is None:
            node = Node(id=resource.address, resource=resource)
            self._nodes[node.id] = node
            self._out.setdefault(node.id, [])
        return node

    def add_edge(self, src: str, dst: str, kind: EdgeKind) -> None:
        # Only connect nodes we actually know about; a dangling reference to a
        # resource declared elsewhere is simply ignored.
        if src in self._nodes and dst in self._nodes:
            edge = Edge(src, dst, kind)
            if edge not in self._out[src]:
                self._out[src].append(edge)

    def node(self, node_id: str) -> Node | None:
        return self._nodes.get(node_id)

    def nodes(self) -> list[Node]:
        return list(self._nodes.values())

    def edges_from(self, node_id: str) -> list[Edge]:
        return self._out.get(node_id, [])

    def nodes_with_role(self, role: NodeRole) -> list[Node]:
        return [n for n in self._nodes.values() if n.has(role)]

    def __len__(self) -> int:
        return len(self._nodes)
