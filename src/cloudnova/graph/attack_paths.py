"""Find attack paths: walks from an internet-exposed node to a sensitive target.

An attack path is a chain of relationships an attacker could follow. We do a
bounded depth-first search from every internet-exposed compute node, following
CAN_ASSUME / GRANTS / REFERENCES edges, and report a path when it reaches a node
that is privileged (can escalate) or a data store (can exfiltrate). Each path
becomes a CRITICAL :class:`Finding` with a human narration of the chain — the
output that makes the risk obvious in a way a flat finding list cannot.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise

from cloudnova.core.findings import Confidence, Finding, Location, Severity
from cloudnova.graph.model import EdgeKind, Node, NodeRole, ResourceGraph

#: Don't chase chains longer than this — keeps search bounded and paths readable.
_MAX_DEPTH = 6

_EDGE_VERB = {
    EdgeKind.PROTECTED_BY: "is protected by",
    EdgeKind.CAN_ASSUME: "can assume",
    EdgeKind.GRANTS: "is granted",
    EdgeKind.REFERENCES: "references",
}


@dataclass(frozen=True)
class AttackPath:
    """An exploitable chain from an exposed entry point to a sensitive target."""

    nodes: tuple[str, ...]
    reason: str

    @property
    def entry(self) -> str:
        return self.nodes[0]

    @property
    def target(self) -> str:
        return self.nodes[-1]


def _is_target(node: Node, entry_id: str) -> bool:
    """A useful endpoint: privileged escalation or data access, and not the entry."""
    if node.id == entry_id:
        return False
    return node.has(NodeRole.PRIVILEGED) or node.has(NodeRole.DATA_STORE)


def _narrate(graph: ResourceGraph, path: list[str]) -> str:
    """Render a node-id path as a readable sentence with edge verbs."""
    parts = [path[0]]
    for src, dst in pairwise(path):
        kind = next((e.kind for e in graph.edges_from(src) if e.dst == dst), EdgeKind.REFERENCES)
        parts.append(f"— {_EDGE_VERB[kind]} → {dst}")
    return " ".join(parts)


def find_attack_paths(graph: ResourceGraph) -> list[AttackPath]:
    """Return every attack path from an internet-exposed node to a target."""
    paths: list[AttackPath] = []
    seen_targets: set[tuple[str, str]] = set()

    for entry in graph.nodes_with_role(NodeRole.INTERNET_EXPOSED):
        stack: list[tuple[str, list[str]]] = [(entry.id, [entry.id])]
        while stack:
            current_id, trail = stack.pop()
            if len(trail) > _MAX_DEPTH:
                continue
            current = graph.node(current_id)
            if current is not None and _is_target(current, entry.id):
                key = (entry.id, current_id)
                if key not in seen_targets:
                    seen_targets.add(key)
                    paths.append(AttackPath(tuple(trail), _describe(current)))
                # Don't stop — a data store reached via a role may still lead on,
                # but avoid revisiting nodes already in this trail (no cycles).
            for edge in graph.edges_from(current_id):
                if edge.dst not in trail:
                    stack.append((edge.dst, [*trail, edge.dst]))

    return paths


def _describe(target: Node) -> str:
    if target.has(NodeRole.PRIVILEGED):
        return "reaches a privileged identity (privilege escalation to admin)"
    return "reaches a sensitive data store (data exfiltration)"


def paths_to_findings(graph: ResourceGraph, path_list: list[AttackPath]) -> list[Finding]:
    """Turn attack paths into CRITICAL findings for the normal reporting flow."""
    findings: list[Finding] = []
    for path in path_list:
        entry_node = graph.node(path.entry)
        source_path = entry_node.resource.path if entry_node else "<graph>"
        narration = _narrate(graph, list(path.nodes))
        findings.append(
            Finding(
                check_id="GRAPH_ATTACK_PATH",
                title="Exploitable attack path from an internet-exposed resource",
                severity=Severity.CRITICAL,
                confidence=Confidence.MEDIUM,
                location=Location(path=source_path, resource=path.entry),
                description=(
                    f"An attacker who compromises the internet-exposed resource "
                    f"'{path.entry}' {path.reason}. Chain: {narration}."
                ),
                remediation=(
                    "Break the chain: restrict the entry point's exposure, scope the IAM "
                    "permissions along the path to least privilege, or isolate the target."
                ),
                evidence=narration,
                mitre_attack=["T1078", "T1098", "T1530"],
            )
        )
    return findings
