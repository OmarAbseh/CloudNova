"""Attack-path graph over CloudFormation templates (Ref / Fn::GetAtt edges)."""

from cloudnova.core.parsers import cloudformation
from cloudnova.graph import build_graph, find_attack_paths
from cloudnova.graph.model import EdgeKind, NodeRole

_CHAIN = """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  WebSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
  WebInstance:
    Type: AWS::EC2::Instance
    Properties:
      SecurityGroupIds: [!Ref WebSG]
      IamInstanceProfile: !Ref AppProfile
  AppProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Roles: [!Ref AppRole]
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      Policies:
        - PolicyName: admin
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action: "*"
                Resource: "*"
"""


def _graph(text: str):
    return build_graph(cloudformation.parse(text))


def test_cfn_graph_nodes_and_edges():
    g = _graph(_CHAIN)
    assert len(g) == 4
    kinds = {e.kind for n in g.nodes() for e in g.edges_from(n.id)}
    assert EdgeKind.PROTECTED_BY in kinds
    assert EdgeKind.CAN_ASSUME in kinds


def test_cfn_roles_tagged():
    g = _graph(_CHAIN)
    exposed = {n.id for n in g.nodes_with_role(NodeRole.INTERNET_EXPOSED)}
    privileged = {n.id for n in g.nodes_with_role(NodeRole.PRIVILEGED)}
    assert "AWS::EC2::Instance.WebInstance" in exposed
    assert "AWS::IAM::Role.AppRole" in privileged


def test_cfn_attack_path_found():
    paths = find_attack_paths(_graph(_CHAIN))
    assert len(paths) == 1
    assert paths[0].entry == "AWS::EC2::Instance.WebInstance"
    assert paths[0].target == "AWS::IAM::Role.AppRole"


def test_cfn_no_path_when_restricted():
    safe = _CHAIN.replace("0.0.0.0/0", "10.0.0.0/8")
    assert find_attack_paths(_graph(safe)) == []


def test_cfn_no_path_when_scoped_policy():
    scoped = _CHAIN.replace('Action: "*"', "Action: s3:GetObject").replace(
        'Resource: "*"', 'Resource: "arn:aws:s3:::b/*"'
    )
    assert find_attack_paths(_graph(scoped)) == []
