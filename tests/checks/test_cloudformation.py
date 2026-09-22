"""CloudFormation check pack: positive + negative per rule, plus intrinsic tags."""

from pathlib import Path

from cloudnova.core.engine import Engine


def _ids(root: Path) -> set[str]:
    return {f.check_id for f in Engine().scan_path(root).findings}


def _write(tmp_path: Path, body: str, name: str = "stack.yaml") -> Path:
    (tmp_path / name).write_text(body, encoding="utf-8")
    return tmp_path


_HEADER = 'AWSTemplateFormatVersion: "2010-09-09"\nResources:\n'


def test_s3_public_acl_flagged(tmp_path):
    root = _write(
        tmp_path,
        _HEADER
        + "  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      AccessControl: PublicRead\n",
    )
    assert "CFN_S3_PUBLIC_ACL" in _ids(root)


def test_s3_private_not_flagged(tmp_path):
    root = _write(
        tmp_path,
        _HEADER + "  B:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        "      AccessControl: Private\n      BucketEncryption: {}\n",
    )
    assert "CFN_S3_PUBLIC_ACL" not in _ids(root)


def test_intrinsic_tags_do_not_break_parsing(tmp_path):
    # !Sub / !GetAtt must parse cleanly, not raise.
    root = _write(
        tmp_path,
        _HEADER + "  B:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        '      BucketName: !Sub "${AWS::StackName}-x"\n      BucketEncryption: {}\n',
    )
    result = Engine().scan_path(root)
    assert not result.errors


def test_sg_world_ssh_is_critical(tmp_path):
    root = _write(
        tmp_path,
        _HEADER + "  SG:\n    Type: AWS::EC2::SecurityGroup\n    Properties:\n"
        "      SecurityGroupIngress:\n        - FromPort: 22\n          ToPort: 22\n"
        "          CidrIp: 0.0.0.0/0\n",
    )
    sg = [f for f in Engine().scan_path(root).findings if f.check_id == "CFN_SG_WORLD_INGRESS"]
    assert sg and sg[0].severity.value == "critical"


def test_sg_restricted_not_flagged(tmp_path):
    root = _write(
        tmp_path,
        _HEADER + "  SG:\n    Type: AWS::EC2::SecurityGroup\n    Properties:\n"
        "      SecurityGroupIngress:\n        - FromPort: 22\n          CidrIp: 10.0.0.0/8\n",
    )
    assert "CFN_SG_WORLD_INGRESS" not in _ids(root)


def test_iam_wildcard_flagged(tmp_path):
    root = _write(
        tmp_path,
        _HEADER + "  P:\n    Type: AWS::IAM::Policy\n    Properties:\n"
        "      PolicyDocument:\n        Statement:\n"
        '          - Effect: Allow\n            Action: "*"\n            Resource: "*"\n',
    )
    iam = [f for f in Engine().scan_path(root).findings if f.check_id == "CFN_IAM_WILDCARD"]
    assert iam and iam[0].severity.value == "critical"


def test_iam_scoped_not_flagged(tmp_path):
    root = _write(
        tmp_path,
        _HEADER + "  P:\n    Type: AWS::IAM::Policy\n    Properties:\n"
        "      PolicyDocument:\n        Statement:\n"
        "          - Effect: Allow\n            Action: s3:GetObject\n"
        '            Resource: "arn:x"\n',
    )
    assert "CFN_IAM_WILDCARD" not in _ids(root)


def test_json_template_classified_as_cfn(tmp_path):
    body = (
        '{"Resources": {"B": {"Type": "AWS::S3::Bucket",'
        ' "Properties": {"AccessControl": "PublicRead"}}}}'
    )
    root = _write(tmp_path, body, name="template.json")
    assert "CFN_S3_PUBLIC_ACL" in _ids(root)
