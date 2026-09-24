"""Shared AWS security primitives used by multiple check packs.

Terraform, CloudFormation, and CloudTrail checks all reason about the same AWS
concepts — public ACLs, world-open CIDRs, sensitive ports, and IAM policy
statements. Centralizing them here keeps the rules consistent and DRY: fix the
definition of "public ACL" once and every pack agrees.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

#: Canned S3 ACLs that grant access beyond the account owner.
PUBLIC_ACLS: frozenset[str] = frozenset(
    {"public-read", "public-read-write", "authenticated-read", "PublicRead", "PublicReadWrite"}
)

#: CIDRs meaning "the entire internet".
WORLD_CIDRS: frozenset[str] = frozenset({"0.0.0.0/0", "::/0"})

#: Ports especially dangerous to expose to the world, with a friendly name.
SENSITIVE_PORTS: dict[int, str] = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
}


def as_list(value: Any) -> list[Any]:
    """Treat a scalar or a list uniformly as a list (IAM fields are either)."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def iter_policy_statements(policy: Any) -> Iterator[dict[str, Any]]:
    """Yield statements from an IAM policy that may be a dict or a JSON string.

    ``Statement`` may be a single object or a list. Never raises on malformed
    input — a policy we can't parse simply yields nothing.
    """
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError:
            return
    if not isinstance(policy, dict):
        return
    statements = policy.get("Statement")
    if isinstance(statements, dict):
        yield statements
    elif isinstance(statements, list):
        yield from (s for s in statements if isinstance(s, dict))


def wildcard_kind(statement: dict[str, Any]) -> tuple[bool, bool] | None:
    """Return (action_wildcard, resource_wildcard) for an Allow statement.

    Returns ``None`` if the statement is not an Allow or has no wildcard, so a
    caller can ``if (kind := wildcard_kind(s)) is None: continue``.
    """
    if statement.get("Effect") != "Allow":
        return None
    action_wild = "*" in as_list(statement.get("Action"))
    resource_wild = "*" in as_list(statement.get("Resource"))
    if not (action_wild or resource_wild):
        return None
    return action_wild, resource_wild
