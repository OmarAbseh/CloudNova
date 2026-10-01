"""Scope-gated guided lab sessions.

A lab session is how the Mentor teaches hands-on: it names a *practice target* and
walks you through a professional methodology checklist against it. Because it
names a target, it MUST pass the Range scope engine first - the same gate every
Range capability uses. Point it at a practice box (TryHackMe/HTB/local Juice Shop)
you've listed in your scope file; anything unauthorized is refused.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cloudnova.range.scope import Decision, Scope


@dataclass(frozen=True)
class LabPlan:
    """A guided, methodology-driven plan for a practice engagement."""

    target: str
    decision: Decision
    phases: list[tuple[str, list[str]]] = field(default_factory=list)

    @property
    def authorized(self) -> bool:
        return self.decision.allowed


# A professional engagement methodology, phase by phase. This is the *how to
# think* checklist, the same flow taught by OSCP/PNPT, not target-specific
# exploit steps.
_METHODOLOGY: list[tuple[str, list[str]]] = [
    (
        "1. Scope & notes",
        [
            "Confirm the target is in scope (this session already checked).",
            "Start a notes file: timestamp everything, screenshot as you go.",
        ],
    ),
    (
        "2. Reconnaissance",
        [
            "Enumerate services and versions (nmap) - only against the in-scope target.",
            "For web: browse the app first as a normal user; map the functionality.",
            "Record every open port/service/endpoint before touching anything.",
        ],
    ),
    (
        "3. Enumeration",
        [
            "Dig into each service: directories, parameters, versions, default creds.",
            "For web: proxy through Burp; catalogue every request/parameter.",
            "Form hypotheses: which vuln classes could each surface have?",
        ],
    ),
    (
        "4. Exploitation (validate a hypothesis)",
        [
            "Test one hypothesis at a time; confirm impact minimally and safely.",
            "Capture the exact request/response that proves the issue.",
            "Stop and note as soon as it's confirmed - don't cause damage.",
        ],
    ),
    (
        "5. Post-exploitation (if in scope)",
        [
            "Enumerate for privilege escalation using the privesc modules.",
            "Only go as far as the rules of engagement allow.",
        ],
    ),
    (
        "6. Reporting",
        [
            "Write each finding: severity, reproduction steps, impact, remediation.",
            "Use `cloudnova` to help draft the finding in a consistent format.",
        ],
    ),
]


def start_lab_session(target: str, scope: Scope) -> LabPlan:
    """Authorize ``target`` against ``scope`` and, if allowed, return a guided plan."""
    decision = scope.authorize(target)
    phases = _METHODOLOGY if decision.allowed else []
    return LabPlan(target=target, decision=decision, phases=phases)
