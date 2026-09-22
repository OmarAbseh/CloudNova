"""Unit tests for the pure text->data parsers."""

from cloudnova.core.parsers import terraform
from cloudnova.core.resource import IaCFormat


def test_terraform_parse_basic():
    resources = terraform.parse(
        'resource "aws_s3_bucket" "data" {\n  bucket = "x"\n  acl = "private"\n}\n'
    )
    assert len(resources) == 1
    r = resources[0]
    assert r.format is IaCFormat.TERRAFORM
    assert r.type == "aws_s3_bucket"
    assert r.name == "data"
    assert r.address == "aws_s3_bucket.data"
    assert r.get("bucket") == "x"


def test_resolve_jsonencode():
    val = '${jsonencode({Statement = [{Effect = "Allow", Action = "*"}]})}'
    out = terraform.resolve_jsonencode(val)
    assert out["Statement"][0]["Action"] == "*"


def test_resolve_jsonencode_passthrough_on_plain_string():
    assert terraform.resolve_jsonencode("just-a-string") == "just-a-string"


def test_terraform_parse_error_raises():
    import pytest

    with pytest.raises(terraform.TerraformParseError):
        terraform.parse("resource {{{ broken")


def test_cloudformation_detects_and_parses():
    from cloudnova.core.parsers import cloudformation

    text = (
        'AWSTemplateFormatVersion: "2010-09-09"\n'
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n"
        "    Properties:\n      AccessControl: Private\n"
    )
    data = cloudformation.load_template(text)
    assert cloudformation.looks_like_cloudformation(data)
    resources = cloudformation.parse_data(data)
    assert resources[0].type == "AWS::S3::Bucket"
    assert resources[0].name == "B"


def test_cloudformation_rejects_generic_yaml():
    from cloudnova.core.parsers import cloudformation

    data = {"access_control": {"public": True}}
    assert not cloudformation.looks_like_cloudformation(data)
