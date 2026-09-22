"""Attack-path graph: build a graph from resources and find exploitable chains."""

from cloudnova.core.parsers.terraform import parse
from cloudnova.graph import build_graph, find_attack_paths
from cloudnova.graph.attack_paths import paths_to_findings
from cloudnova.graph.model import EdgeKind, NodeRole

_CHAIN = """
resource "aws_security_group" "web" {
  ingress { from_port = 22
    to_port = 22
    cidr_blocks = ["0.0.0.0/0"] }
}
resource "aws_instance" "web" {
  vpc_security_group_ids = [aws_security_group.web.id]
  iam_instance_profile   = aws_iam_instance_profile.app.name
}
resource "aws_iam_instance_profile" "app" { role = aws_iam_role.app.name }
resource "aws_iam_role" "app" { name = "app" }
resource "aws_iam_role_policy" "admin" {
  role   = aws_iam_role.app.id
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
}
"""


def _graph(tf: str):
    return build_graph(parse(tf))


def test_graph_has_all_nodes():
    g = _graph(_CHAIN)
    assert len(g) == 5


def test_edges_are_classified():
    g = _graph(_CHAIN)
    kinds = {e.kind for n in g.nodes() for e in g.edges_from(n.id)}
    assert EdgeKind.PROTECTED_BY in kinds
    assert EdgeKind.CAN_ASSUME in kinds
    assert EdgeKind.GRANTS in kinds


def test_roles_are_tagged():
    g = _graph(_CHAIN)
    exposed = {n.id for n in g.nodes_with_role(NodeRole.INTERNET_EXPOSED)}
    privileged = {n.id for n in g.nodes_with_role(NodeRole.PRIVILEGED)}
    assert "aws_instance.web" in exposed
    assert "aws_iam_role.app" in privileged


def test_attack_path_found():
    paths = find_attack_paths(_graph(_CHAIN))
    assert len(paths) == 1
    p = paths[0]
    assert p.entry == "aws_instance.web"
    assert p.target == "aws_iam_role.app"


def test_attack_path_becomes_critical_finding():
    g = _graph(_CHAIN)
    findings = paths_to_findings(g, find_attack_paths(g))
    assert findings and findings[0].severity.value == "critical"
    assert findings[0].check_id == "GRAPH_ATTACK_PATH"


def test_no_path_when_not_exposed():
    # Same chain but the SG is not world-open -> no exposed entry -> no path.
    safe = _CHAIN.replace('"0.0.0.0/0"', '"10.0.0.0/8"')
    assert find_attack_paths(_graph(safe)) == []


def test_no_path_without_privilege():
    # Exposed instance but the role has only a scoped policy -> no target.
    scoped = _CHAIN.replace(
        'Action = "*", Resource = "*"',
        'Action = "s3:GetObject", Resource = "arn:aws:s3:::b/*"',
    )
    assert find_attack_paths(_graph(scoped)) == []


def test_dangling_reference_ignored():
    # Reference to a resource declared elsewhere must not crash or add an edge.
    tf = 'resource "aws_instance" "a" { subnet_id = aws_subnet.missing.id }'
    g = _graph(tf)
    assert len(g) == 1
    assert find_attack_paths(g) == []


def test_cycle_does_not_hang():
    tf = """
    resource "aws_iam_role" "a" { assume_role_policy = aws_iam_role.b.arn }
    resource "aws_iam_role" "b" { assume_role_policy = aws_iam_role.a.arn }
    """
    # Must terminate; no exposed entry so no paths, but the point is no infinite loop.
    assert find_attack_paths(_graph(tf)) == []
