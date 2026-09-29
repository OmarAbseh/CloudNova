"""IAM generator: authors least-privilege policies from a grant spec."""

import pytest

from cloudnova.iam import GenerationError, analyze_policy, generate_policy


def test_generates_scoped_policy():
    spec = {
        "grants": [
            {
                "service": "s3",
                "access": ["read", "list"],
                "resources": ["arn:aws:s3:::b", "arn:aws:s3:::b/*"],
            }
        ]
    }
    policy = generate_policy(spec)
    assert policy["Version"] == "2012-10-17"
    stmt = policy["Statement"][0]
    assert "s3:GetObject" in stmt["Action"]
    assert "s3:ListBucket" in stmt["Action"]
    assert stmt["Resource"] == ["arn:aws:s3:::b", "arn:aws:s3:::b/*"]
    # Least privilege: no wildcard actions.
    assert "*" not in stmt["Action"]


def test_round_trip_generated_policy_is_clean():
    # The generator's output must pass the analyzer with zero findings — the
    # proof that what it authors is genuinely least-privilege.
    spec = {
        "grants": [
            {"service": "s3", "access": ["read"], "resources": ["arn:aws:s3:::b/*"]},
            {
                "service": "dynamodb",
                "access": ["read", "write"],
                "resources": ["arn:aws:dynamodb:us-east-1:1:table/T"],
            },
            {
                "service": "secretsmanager",
                "access": "read",
                "resources": ["arn:aws:secretsmanager:us-east-1:1:secret:x-*"],
            },
        ]
    }
    assert analyze_policy(generate_policy(spec)) == []


def test_rejects_wildcard_resource():
    spec = {"grants": [{"service": "s3", "access": "read", "resources": ["*"]}]}
    with pytest.raises(GenerationError, match="least-privilege"):
        generate_policy(spec)


def test_rejects_unknown_service():
    spec = {"grants": [{"service": "quantumdb", "access": "read", "resources": ["arn:x"]}]}
    with pytest.raises(GenerationError, match="Unsupported service"):
        generate_policy(spec)


def test_rejects_unknown_access():
    spec = {"grants": [{"service": "s3", "access": "teleport", "resources": ["arn:x"]}]}
    with pytest.raises(GenerationError, match="Unsupported access"):
        generate_policy(spec)


def test_rejects_empty_spec():
    with pytest.raises(GenerationError):
        generate_policy({"grants": []})
