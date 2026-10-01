"""Assess findings against a compliance framework.

Given the check ids that fired in a scan, mark each catalog control as:
- FAIL: at least one finding maps to it,
- PASS: the control is one CloudNova assesses and nothing failed it,
- NOT_ASSESSED: in the catalog but outside what CloudNova currently checks.

The compliance score is passed / (passed + failed) - honest about coverage: it
never counts controls we don't actually test.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum

from cloudnova.compliance.frameworks import (
    CATALOGS,
    CATEGORY_CONTROLS,
    Category,
    Framework,
    categorize,
)


class ControlState(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_ASSESSED = "NOT_ASSESSED"


@dataclass
class ControlResult:
    framework: Framework
    control_id: str
    title: str
    state: ControlState
    failing_checks: list[str] = field(default_factory=list)


@dataclass
class ComplianceReport:
    framework: Framework
    controls: list[ControlResult]

    @property
    def failed(self) -> list[ControlResult]:
        return [c for c in self.controls if c.state is ControlState.FAIL]

    @property
    def passed(self) -> list[ControlResult]:
        return [c for c in self.controls if c.state is ControlState.PASS]

    @property
    def assessed(self) -> list[ControlResult]:
        return [c for c in self.controls if c.state is not ControlState.NOT_ASSESSED]

    @property
    def score(self) -> int:
        n = len(self.assessed)
        return round(100 * len(self.passed) / n) if n else 0


def _assessable_controls(framework: Framework) -> set[str]:
    """Controls CloudNova can actually evaluate (reachable from our categories)."""
    out: set[str] = set()
    for controls in CATEGORY_CONTROLS[framework].values():
        out.update(controls)
    return out


def assess(check_ids: Iterable[str], framework: Framework) -> ComplianceReport:
    """Assess the given fired check ids against a framework's controls."""
    controls_map = CATEGORY_CONTROLS[framework]
    failing: dict[str, list[str]] = {}
    for cid in check_ids:
        category = categorize(cid)
        if category is Category.OTHER:
            continue
        for control_id in controls_map.get(category, []):
            failing.setdefault(control_id, [])
            if cid not in failing[control_id]:
                failing[control_id].append(cid)

    assessable = _assessable_controls(framework)
    results: list[ControlResult] = []
    for control_id, title in CATALOGS[framework].items():
        if control_id in failing:
            state = ControlState.FAIL
        elif control_id in assessable:
            state = ControlState.PASS
        else:
            state = ControlState.NOT_ASSESSED
        results.append(
            ControlResult(
                framework=framework,
                control_id=control_id,
                title=title,
                state=state,
                failing_checks=sorted(failing.get(control_id, [])),
            )
        )
    return ComplianceReport(framework=framework, controls=results)


def assess_all(check_ids: Iterable[str]) -> dict[Framework, ComplianceReport]:
    ids = list(check_ids)
    return {fw: assess(ids, fw) for fw in Framework}
