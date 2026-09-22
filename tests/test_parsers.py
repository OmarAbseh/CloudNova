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
