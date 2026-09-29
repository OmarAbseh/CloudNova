"""Data model for the blackbox pentest checklist (PTES + OWASP WSTG).

Mirrors the states in the source checklist (PASS / FAIL / N/A) and adds a TODO
state for manual items an operator must still perform. Automatable items are run
passively by the web-assessment engine; manual items carry methodology guidance
and stay the operator's responsibility — the tool never exploits on its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class State(StrEnum):
    PASS = "PASS"  # Secure / no vulnerability
    FAIL = "FAIL"  # Vulnerability found / finding to report
    NA = "N/A"  # Not applicable to this system
    TODO = "TODO"  # Manual test the operator still needs to run
    INFO = "INFO"  # Informational observation, not a pass/fail


class Mode(StrEnum):
    AUTO = "auto"  # CloudNova checks this passively (always run)
    ACTIVE = "active"  # Intrusive *detection* — opt-in (--active), scope-gated
    MANUAL = "manual"  # Needs operator judgment/context; tracked, never auto-exploited


@dataclass(frozen=True)
class ChecklistItem:
    """One test case from the methodology."""

    id: str
    phase: str
    test_case: str
    description: str
    tools: str
    mode: Mode
    asvs: str = ""


@dataclass
class RunItem:
    """An item after a run: its resolved state and any evidence."""

    item: ChecklistItem
    state: State
    findings: list[str] = field(default_factory=list)


@dataclass
class ChecklistRun:
    """The result of running the checklist against one authorized target."""

    target: str
    authorized: bool
    attestation: str
    items: list[RunItem] = field(default_factory=list)

    def by_state(self, state: State) -> list[RunItem]:
        return [ri for ri in self.items if ri.state is state]

    @property
    def failed(self) -> list[RunItem]:
        return self.by_state(State.FAIL)

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {s.value: 0 for s in State}
        for ri in self.items:
            out[ri.state.value] += 1
        return out
