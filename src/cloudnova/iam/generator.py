"""Generate a least-privilege IAM policy from a high-level grant spec.

You describe *what* an application needs - "read and list this S3 bucket", "write
to that DynamoDB table" - and the generator emits a scoped IAM policy with only
the specific actions those intents require, constrained to the resource ARNs you
name. It refuses to emit wildcard resources, so its output is least-privilege by
construction; tests then run the analyzer over the result to prove it's clean.

Grant spec shape::

    {
      "grants": [
        {"service": "s3", "access": ["read", "list"],
         "resources": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]},
      ]
    }
"""

from __future__ import annotations

from typing import Any

# service -> access level -> concrete actions. Curated for least privilege; each
# access level maps to the minimal common actions for that intent.
_ACTIONS: dict[str, dict[str, list[str]]] = {
    "s3": {
        "read": ["s3:GetObject", "s3:GetObjectVersion"],
        "write": ["s3:PutObject", "s3:DeleteObject"],
        "list": ["s3:ListBucket", "s3:GetBucketLocation"],
    },
    "dynamodb": {
        "read": ["dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan"],
        "write": [
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "dynamodb:DeleteItem",
            "dynamodb:BatchWriteItem",
        ],
    },
    "sqs": {
        "read": ["sqs:ReceiveMessage", "sqs:GetQueueAttributes"],
        "write": ["sqs:SendMessage"],
    },
    "sns": {"publish": ["sns:Publish"]},
    "secretsmanager": {"read": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]},
    "kms": {"use": ["kms:Decrypt", "kms:GenerateDataKey", "kms:Encrypt"]},
    "lambda": {"invoke": ["lambda:InvokeFunction"]},
    "logs": {
        "write": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
    },
}


class GenerationError(ValueError):
    """Raised when a grant spec is invalid or can't be satisfied."""


def supported() -> dict[str, list[str]]:
    """Return the supported ``service -> [access levels]`` map (for help/UX)."""
    return {service: sorted(levels) for service, levels in _ACTIONS.items()}


def _actions_for(service: str, access: str) -> list[str]:
    service = service.lower()
    access = access.lower()
    if service not in _ACTIONS:
        raise GenerationError(
            f"Unsupported service {service!r}. Supported: {', '.join(sorted(_ACTIONS))}."
        )
    if access not in _ACTIONS[service]:
        raise GenerationError(
            f"Unsupported access {access!r} for {service!r}. "
            f"Supported: {', '.join(sorted(_ACTIONS[service]))}."
        )
    return _ACTIONS[service][access]


def _statement(grant: dict[str, Any], index: int) -> dict[str, Any]:
    service = grant.get("service")
    if not isinstance(service, str):
        raise GenerationError(f"grant #{index}: 'service' is required and must be a string.")
    access_levels = grant.get("access")
    if isinstance(access_levels, str):
        access_levels = [access_levels]
    if not isinstance(access_levels, list) or not access_levels:
        raise GenerationError(f"grant #{index}: 'access' must be a non-empty list.")

    resources = grant.get("resources")
    if isinstance(resources, str):
        resources = [resources]
    if not isinstance(resources, list) or not resources:
        raise GenerationError(f"grant #{index}: 'resources' must be a non-empty list of ARNs.")
    if any(r == "*" for r in resources):
        raise GenerationError(
            f"grant #{index}: wildcard resource '*' is not least-privilege; name specific ARNs."
        )

    actions: list[str] = []
    for access in access_levels:
        for action in _actions_for(service, access):
            if action not in actions:
                actions.append(action)

    sid = service.capitalize() + "".join(a.capitalize() for a in access_levels)
    return {
        "Sid": sid,
        "Effect": "Allow",
        "Action": sorted(actions),
        "Resource": list(resources),
    }


def generate_policy(spec: dict[str, Any]) -> dict[str, Any]:
    """Build a least-privilege IAM policy document from a grant spec."""
    grants = spec.get("grants")
    if not isinstance(grants, list) or not grants:
        raise GenerationError("spec must contain a non-empty 'grants' list.")
    statements = [_statement(g, i) for i, g in enumerate(grants) if isinstance(g, dict)]
    if not statements:
        raise GenerationError("no valid grants found in spec.")
    return {"Version": "2012-10-17", "Statement": statements}
