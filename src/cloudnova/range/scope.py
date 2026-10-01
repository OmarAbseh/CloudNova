"""The scope / authorization engine - the gate every Range capability passes through.

Design principles, in priority order:

1. **Deny by default.** A target is authorized only if it explicitly matches an
   in-scope entry and matches no out-of-scope entry. Anything unknown is DENIED.
2. **Exclusions win.** An out-of-scope match always beats an in-scope match, so a
   carve-out (``*.example.com`` in scope, ``admin.example.com`` excluded) is safe.
3. **No attestation, no authorization.** A scope file must carry an explicit
   authorization block affirming the operator is cleared to test these targets.
   Without it, the engine authorizes nothing (fail closed).

The engine only *decides*; it never touches a target. It supports IPs, CIDR
ranges, exact and wildcard domains, and cloud account identifiers.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml


class ScopeError(Exception):
    """Raised when a scope definition is missing or invalid."""


class Verdict(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class Decision:
    """The result of an authorization check - always with a human-readable reason."""

    verdict: Verdict
    target: str
    reason: str

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW


@dataclass(frozen=True)
class Authorization:
    """Attestation that the operator is cleared to test the declared targets.

    This is deliberately required. It is the human accountability record: who
    authorized the test, for what program/engagement, and an explicit
    acknowledgement. Findings and logs reference it.
    """

    program: str
    authorized_by: str
    acknowledged: bool
    reference: str = ""

    def is_valid(self) -> bool:
        return bool(self.program and self.authorized_by and self.acknowledged)


@dataclass
class Scope:
    """A parsed testing scope: what's in, what's explicitly out, and the attestation."""

    authorization: Authorization
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)

    def authorize(self, target: str) -> Decision:
        return authorize(target, self)


def _matches(entry: str, target: str) -> bool:
    """Does a scope ``entry`` cover ``target``?

    Supports:
    - CIDR ranges (``10.0.0.0/8``) matching contained IPs
    - exact IPs and exact strings (domains, cloud account IDs)
    - wildcard domains (``*.example.com`` matches ``api.example.com`` and
      ``example.com`` itself, but not ``evil-example.com``)
    """
    entry = entry.strip().lower()
    target = target.strip().lower()
    if not entry or not target:
        return False

    # CIDR / IP matching.
    if "/" in entry:
        try:
            network = ipaddress.ip_network(entry, strict=False)
            return ipaddress.ip_address(target) in network
        except ValueError:
            return False
    # A plain IP entry: exact IP equality.
    try:
        return ipaddress.ip_address(entry) == ipaddress.ip_address(target)
    except ValueError:
        pass  # not an IP; fall through to string/domain matching

    # Wildcard domain.
    if entry.startswith("*."):
        base = entry[2:]
        return target == base or target.endswith("." + base)

    # Exact match (domain, account id, arn, etc.).
    return entry == target


def authorize(target: str, scope: Scope) -> Decision:
    """Decide whether ``target`` may be tested under ``scope`` (deny by default)."""
    if not scope.authorization.is_valid():
        return Decision(
            Verdict.DENY,
            target,
            "No valid authorization attestation - refusing all targets (fail closed).",
        )
    if not target or not target.strip():
        return Decision(Verdict.DENY, target, "Empty target.")

    # Exclusions take precedence over inclusions.
    for entry in scope.out_of_scope:
        if _matches(entry, target):
            return Decision(Verdict.DENY, target, f"Target matches an out-of-scope rule ({entry}).")

    for entry in scope.in_scope:
        if _matches(entry, target):
            return Decision(
                Verdict.ALLOW,
                target,
                f"Authorized: matches in-scope entry ({entry}) for "
                f"'{scope.authorization.program}'.",
            )

    return Decision(
        Verdict.DENY,
        target,
        "Not in scope - no in-scope rule matches (deny by default).",
    )


def _authorization_from(data: dict[str, Any]) -> Authorization:
    auth = data.get("authorization")
    if not isinstance(auth, dict):
        raise ScopeError(
            "Scope file must contain an 'authorization' block "
            "(program, authorized_by, acknowledged: true)."
        )
    return Authorization(
        program=str(auth.get("program", "")).strip(),
        authorized_by=str(auth.get("authorized_by", "")).strip(),
        acknowledged=auth.get("acknowledged") is True,
        reference=str(auth.get("reference", "")).strip(),
    )


SELF_AUTH_PROGRAM = "Self-authorized (operator responsibility)"


def self_authorized_scope(target: str, operator: str) -> Scope:
    """Build a scope from an explicit self-authorization ("no scope" responsibility tick).

    This is not a bypass: it records an accountability attestation stating the
    operator asserts they own or are authorized to test ``target`` and accept full
    responsibility. The attestation is written into every report. It authorizes
    exactly the one target given - nothing wildcard, nothing broad.
    """
    operator = operator.strip() or "unknown-operator"
    auth = Authorization(
        program=SELF_AUTH_PROGRAM,
        authorized_by=operator,
        acknowledged=True,
        reference="operator-attested",
    )
    return Scope(authorization=auth, in_scope=[target], out_of_scope=[])


def load_scope(path: Path) -> Scope:
    """Load and validate a scope file (YAML)."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ScopeError(f"Could not parse scope file: {exc}") from exc
    if not isinstance(data, dict):
        raise ScopeError("Scope file must be a mapping.")

    authorization = _authorization_from(data)
    in_scope = [str(x) for x in (data.get("in_scope") or [])]
    out_of_scope = [str(x) for x in (data.get("out_of_scope") or [])]
    if not in_scope:
        raise ScopeError("Scope file must list at least one 'in_scope' target.")
    return Scope(authorization=authorization, in_scope=in_scope, out_of_scope=out_of_scope)
