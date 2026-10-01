"""Render compliance assessments as a shareable Markdown report (audit evidence)."""

from __future__ import annotations

from datetime import date

from cloudnova.compliance.engine import ComplianceReport, ControlState
from cloudnova.compliance.frameworks import Framework

_LABELS = {
    Framework.ISO_27001: "ISO/IEC 27001",
    Framework.NIST_CSF: "NIST CSF",
    Framework.PCI_DSS: "PCI DSS 4.0",
    Framework.SOC_2: "SOC 2",
    Framework.CIS_V8: "CIS Controls v8",
}
_MARK = {ControlState.PASS: "PASS", ControlState.FAIL: "FAIL", ControlState.NOT_ASSESSED: "n/a"}


def render_markdown(
    reports: dict[Framework, ComplianceReport], *, target: str = "", client: str = ""
) -> str:
    lines: list[str] = [f"# Compliance Report{f' - {client}' if client else ''}"]
    lines.append(f"\n_{date.today():%B %d, %Y}_" + (f" · Target: `{target}`" if target else ""))
    lines.append("\n## Summary\n")
    lines.append("| Framework | Score | Pass | Fail | Assessed |")
    lines.append("|---|---|---|---|---|")
    for fw, rep in reports.items():
        lines.append(
            f"| {_LABELS.get(fw, fw.value)} | {rep.score}% | {len(rep.passed)} | "
            f"{len(rep.failed)} | {len(rep.assessed)} |"
        )
    for fw, rep in reports.items():
        lines.append(f"\n## {_LABELS.get(fw, fw.value)} - {rep.score}%\n")
        lines.append("| Control | Status | Failing checks |")
        lines.append("|---|---|---|")
        for c in rep.controls:
            checks = ", ".join(c.failing_checks) if c.failing_checks else ""
            lines.append(f"| {c.control_id} {c.title} | {_MARK[c.state]} | {checks} |")
    lines.append("")
    return "\n".join(lines)
