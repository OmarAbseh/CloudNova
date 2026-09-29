"""Analyze an IAM policy document for anti-patterns and privilege escalation.

This is a deeper, IAM-specific companion to the wildcard checks in the IaC
packs: it understands *why* an action is dangerous, not just that it's a
wildcard. It flags full admin, service-level wildcards (``iam:*``), known
privilege-escalation actions and combos (``iam:PassRole`` + compute creation),
over-broad trust policies, and ``NotAction`` with Allow.

Findings reuse the core :class:`Finding` model so IAM analysis flows through the
same reporting as everything else.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

from cloudnova.checks._aws import as_list
from cloudnova.core.findings import Confidence, Finding, Location, Severity

# Single actions that alone enable privilege escalation, with severity. Sourced
# from well-documented IAM privilege-escalation research.
_PRIVESC_ACTIONS: dict[str, Severity] = {
    "iam:CreateAccessKey": Severity.HIGH,
    "iam:CreateLoginProfile": Severity.HIGH,
    "iam:UpdateLoginProfile": Severity.HIGH,
    "iam:AttachUserPolicy": Severity.CRITICAL,
    "iam:AttachGroupPolicy": Severity.CRITICAL,
    "iam:AttachRolePolicy": Severity.CRITICAL,
    "iam:PutUserPolicy": Severity.CRITICAL,
    "iam:PutGroupPolicy": Severity.CRITICAL,
    "iam:PutRolePolicy": Severity.CRITICAL,
    "iam:CreatePolicyVersion": Severity.CRITICAL,
    "iam:SetDefaultPolicyVersion": Severity.CRITICAL,
    "iam:AddUserToGroup": Severity.HIGH,
    "iam:UpdateAssumeRolePolicy": Severity.HIGH,
}

# Action sets that together enable escalation. Every action in the set must be
# allowed for the combo to fire.
_PRIVESC_COMBOS: list[tuple[frozenset[str], str]] = [
    (
        frozenset({"iam:PassRole", "ec2:RunInstances"}),
        "pass an existing role to a new EC2 instance and inherit its permissions",
    ),
    (
        frozenset({"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"}),
        "pass a role to a new Lambda function and invoke it",
    ),
    (
        frozenset({"iam:PassRole", "cloudformation:CreateStack"}),
        "pass a role to a CloudFormation stack",
    ),
]

# Services where a service-level wildcard (``svc:*``) is especially dangerous.
_CRITICAL_WILDCARD_SERVICES = {"iam", "sts", "organizations", "kms"}


def _statements(doc: Any) -> list[dict[str, Any]]:
    if not isinstance(doc, dict):
        return []
    stmts = doc.get("Statement")
    if isinstance(stmts, dict):
        return [stmts]
    if isinstance(stmts, list):
        return [s for s in stmts if isinstance(s, dict)]
    return []


def _action_matches(pattern: str, action: str) -> bool:
    """Does an IAM action *pattern* (which may use ``*``) match a concrete action?"""
    pattern = pattern.lower()
    action = action.lower()
    if pattern in ("*", "*:*"):
        return True
    if pattern.endswith(":*"):
        return action.startswith(pattern[:-1])  # "s3:" prefix
    if pattern.endswith("*"):
        return action.startswith(pattern[:-1])
    return pattern == action


def _allow_actions(statements: Iterable[dict[str, Any]]) -> list[str]:
    """All action patterns granted by Allow statements."""
    out: list[str] = []
    for s in statements:
        if s.get("Effect") == "Allow":
            out.extend(str(a) for a in as_list(s.get("Action")))
    return out


def _grants(patterns: list[str], action: str) -> bool:
    return any(_action_matches(p, action) for p in patterns)


def _grants_specifically(patterns: list[str], action: str) -> bool:
    """Granted by a pattern more specific than a full/service wildcard.

    Avoids re-flagging every escalation action when the policy already has a
    ``*`` or ``service:*`` wildcard (which IAM_*_WILDCARD reports on its own).
    """
    service = action.split(":", 1)[0].lower()
    broad = {"*", "*:*", f"{service}:*"}
    return any(p.lower() not in broad and _action_matches(p, action) for p in patterns)


def _finding(
    check_id: str,
    title: str,
    severity: Severity,
    description: str,
    remediation: str,
    source: str,
    *,
    confidence: Confidence = Confidence.HIGH,
    evidence: str | None = None,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        severity=severity,
        confidence=confidence,
        location=Location(path=source),
        description=description,
        remediation=remediation,
        evidence=evidence,
        cis_controls=["CIS AWS 1.16"],
        mitre_attack=["T1098"],
    )


def analyze_policy(doc: Any, source: str = "<policy>") -> list[Finding]:
    """Return findings for a single IAM policy document (identity or resource)."""
    statements = _statements(doc)
    findings: list[Finding] = []
    granted = _allow_actions(statements)

    findings.extend(_check_wildcards(statements, source))
    findings.extend(_check_trust_and_notaction(statements, source))
    findings.extend(_check_privesc_actions(granted, source))
    findings.extend(_check_privesc_combos(granted, source))
    return findings


def _check_wildcards(statements: list[dict[str, Any]], source: str) -> Iterator[Finding]:
    for s in statements:
        if s.get("Effect") != "Allow":
            continue
        actions = [str(a) for a in as_list(s.get("Action"))]
        resources = [str(r) for r in as_list(s.get("Resource"))]
        resource_wild = "*" in resources
        for action in actions:
            if action == "*":
                scope = " on every resource." if resource_wild else "."
                yield _finding(
                    "IAM_FULL_WILDCARD",
                    "Policy allows all actions (Action: '*')",
                    Severity.CRITICAL if resource_wild else Severity.HIGH,
                    f"The statement allows every action{scope}",
                    "Replace '*' with the specific actions the principal needs.",
                    source,
                    evidence="Action: '*'" + (" on Resource: *" if resource_wild else ""),
                )
            elif action.endswith(":*"):
                service = action.split(":", 1)[0]
                sev = Severity.CRITICAL if service in _CRITICAL_WILDCARD_SERVICES else Severity.HIGH
                yield _finding(
                    "IAM_SERVICE_WILDCARD",
                    f"Policy allows all {service} actions ({action})",
                    sev,
                    f"The statement allows every action in the {service} service.",
                    f"List only the specific {service} actions required.",
                    source,
                    evidence=f"Action: {action}",
                )


def _check_trust_and_notaction(statements: list[dict[str, Any]], source: str) -> Iterator[Finding]:
    for s in statements:
        # Over-broad trust / resource policy principal.
        principal = s.get("Principal")
        if s.get("Effect") == "Allow" and _principal_is_wildcard(principal):
            yield _finding(
                "IAM_WILDCARD_PRINCIPAL",
                "Policy trusts any principal (Principal: '*')",
                Severity.CRITICAL,
                "An Allow statement with Principal '*' lets anyone assume this role or use "
                "this resource.",
                "Scope Principal to specific account IDs, roles, or services.",
                source,
                evidence="Principal: '*'",
            )
        # NotAction with Allow is an allow-list inversion that's easy to get wrong.
        if s.get("Effect") == "Allow" and "NotAction" in s:
            yield _finding(
                "IAM_NOTACTION_ALLOW",
                "Allow statement uses NotAction",
                Severity.HIGH,
                "Allow + NotAction grants every action except those listed — usually far "
                "more than intended.",
                "Rewrite as an explicit Allow of the specific actions needed.",
                source,
                confidence=Confidence.MEDIUM,
                evidence="Effect: Allow with NotAction",
            )


def _principal_is_wildcard(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any(v == "*" or (isinstance(v, list) and "*" in v) for v in principal.values())
    return False


def _check_privesc_actions(granted: list[str], source: str) -> Iterator[Finding]:
    for action, severity in _PRIVESC_ACTIONS.items():
        if _grants_specifically(granted, action):
            yield _finding(
                "IAM_PRIVESC_ACTION",
                f"Policy grants a privilege-escalation action ({action})",
                severity,
                f"{action} can be used to grant the principal additional permissions, "
                "escalating to a higher privilege level.",
                f"Remove {action} or tightly scope it with a Resource ARN and Condition.",
                source,
                evidence=action,
            )


def _check_privesc_combos(granted: list[str], source: str) -> Iterator[Finding]:
    for combo, how in _PRIVESC_COMBOS:
        if all(_grants(granted, a) for a in combo):
            yield _finding(
                "IAM_PRIVESC_COMBO",
                "Policy enables a privilege-escalation combination",
                Severity.CRITICAL,
                f"Together, {', '.join(sorted(combo))} let a principal {how}.",
                "Split these permissions across principals, or add Conditions so the role "
                "that can be passed is tightly constrained.",
                source,
                evidence=" + ".join(sorted(combo)),
            )
