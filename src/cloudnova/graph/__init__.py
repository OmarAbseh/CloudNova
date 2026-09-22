"""Attack-path analysis: model resources as a graph and find exploitable chains.

This is what separates CloudNova from a flat checklist scanner. A single public
bucket or one over-privileged role is a finding; the *interesting* risk is the
chain — an internet-exposed instance that can assume an admin role that can read
a sensitive database. This package builds the graph and walks it for such paths.
"""

from cloudnova.graph.attack_paths import AttackPath, find_attack_paths
from cloudnova.graph.builder import build_graph
from cloudnova.graph.model import Edge, EdgeKind, Node, ResourceGraph

__all__ = [
    "AttackPath",
    "Edge",
    "EdgeKind",
    "Node",
    "ResourceGraph",
    "build_graph",
    "find_attack_paths",
]
