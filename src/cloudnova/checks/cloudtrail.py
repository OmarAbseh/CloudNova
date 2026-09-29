"""Checks for AWS CloudTrail event logs.

The old prototype read a flat, hand-shaped ``{"eventName": ..., "Action": ...}``
that real CloudTrail never produces, so it scored zero on genuine logs. These
checks parse the real schema: a top-level ``{"Records": [event, ...]}`` (or a
single event), where IAM policy content lives as a JSON *string* inside
``requestParameters.policyDocument`` and must be parsed again.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any, ClassVar

from cloudnova.core.artifact import Artifact
from cloudnova.core.check import Check, register
from cloudnova.core.findings import Confidence, Finding, Location, Severity


def _events(data: Any) -> list[dict[str, Any]]:
    """Normalise CloudTrail input to a flat list of event dicts.

    Accepts the real ``{"Records": [...]}`` envelope, a bare list, or a single
    event dict — so we are robust to however the log was exported.
    """
    if isinstance(data, dict) and isinstance(data.get("Records"), list):
        return [e for e in data["Records"] if isinstance(e, dict)]
    if isinstance(data, list):
        return [e for e in data if isinstance(e, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def _iter_statements(policy_document: Any) -> Iterator[dict[str, Any]]:
    """Yield each statement from an IAM policy document.

    ``policyDocument`` arrives as a JSON-encoded *string* in CloudTrail; it may
    already be a dict if pre-parsed. ``Statement`` may be a single dict or a
    list. This normalises all of that.
    """
    if isinstance(policy_document, str):
        try:
            policy_document = json.loads(policy_document)
        except json.JSONDecodeError:
            return
    if not isinstance(policy_document, dict):
        return
    statements = policy_document.get("Statement")
    if isinstance(statements, dict):
        yield statements
    elif isinstance(statements, list):
        yield from (s for s in statements if isinstance(s, dict))


def _as_list(value: Any) -> list[Any]:
    """IAM fields are either a scalar or a list; treat both as a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


@register
class WildcardIamPolicy(Check):
    id = "CT_IAM_WILDCARD_ADMIN"
    title = "IAM policy grants wildcard privileges"
    severity = Severity.CRITICAL
    target = "cloudtrail"

    def run(self, artifact: Artifact) -> Iterator[Finding]:
        for event in _events(artifact.data):
            if event.get("eventName") not in {"PutRolePolicy", "PutUserPolicy", "CreatePolicy"}:
                continue
            params = event.get("requestParameters") or {}
            policy = params.get("policyDocument")
            for stmt in _iter_statements(policy):
                if stmt.get("Effect") != "Allow":
                    continue
                actions = _as_list(stmt.get("Action"))
                resources = _as_list(stmt.get("Resource"))
                if "*" in actions and "*" in resources:
                    role = params.get("roleName") or params.get("userName") or "unknown"
                    yield Finding(
                        check_id=self.id,
                        title=self.title,
                        severity=self.severity,
                        confidence=Confidence.HIGH,
                        location=Location(path=artifact.path, resource=str(role)),
                        description=(
                            f"An IAM policy attached to '{role}' allows Action:'*' on "
                            "Resource:'*' — full administrative access, the classic "
                            "privilege-escalation primitive."
                        ),
                        remediation=(
                            "Scope the policy to the specific actions and resource ARNs the "
                            "principal actually needs (least privilege)."
                        ),
                        evidence=json.dumps(stmt, sort_keys=True)[:500],
                        references=[
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
                        ],
                        cis_controls=["CIS AWS 1.16"],
                        mitre_attack=["T1098"],  # Account Manipulation
                    )


@register
class PublicS3Write(Check):
    id = "CT_S3_PUBLIC_ACL"
    title = "S3 object written with a public ACL"
    severity = Severity.HIGH
    target = "cloudtrail"

    _PUBLIC_ACLS: ClassVar[frozenset[str]] = frozenset(
        {"public-read", "public-read-write", "authenticated-read"}
    )

    def run(self, artifact: Artifact) -> Iterator[Finding]:
        for event in _events(artifact.data):
            if event.get("eventName") not in {"PutObject", "PutObjectAcl", "PutBucketAcl"}:
                continue
            params = event.get("requestParameters") or {}
            # The grant is expressed via the x-amz-acl canned ACL, NOT the
            # bucket's *name* — the prototype's fatal confusion.
            acl = params.get("x-amz-acl") or params.get("acl")
            if acl in self._PUBLIC_ACLS:
                bucket = params.get("bucketName", "unknown")
                yield Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=self.severity,
                    confidence=Confidence.HIGH,
                    location=Location(path=artifact.path, resource=str(bucket)),
                    description=(
                        f"An object in bucket '{bucket}' was written with the public "
                        f"canned ACL '{acl}', exposing it to anonymous readers."
                    ),
                    remediation=(
                        "Remove the public ACL and enable S3 Block Public Access at the "
                        "account and bucket level."
                    ),
                    evidence=f"x-amz-acl: {acl}",
                    cis_controls=["CIS AWS 2.1.5"],
                    mitre_attack=["T1530"],
                )
