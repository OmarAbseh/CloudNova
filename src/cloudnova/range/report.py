"""Professional penetration-test report generation.

The report is the deliverable a client pays for — a brilliant finding written up
badly is worthless. This turns an engagement (metadata + findings) into a clean,
conventionally-structured Markdown report: executive summary, methodology,
findings ranked by severity with reproduction and remediation, and an appendix.

It reads an engagement file (YAML) so the tester keeps notes as data and
regenerates the report at will, and it can also fold in :class:`Finding` objects
straight from a CloudNova scan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cloudnova.core.findings import Finding, Severity

_SEV_ORDER = {s: -s.rank for s in Severity}


@dataclass(frozen=True)
class ReportFinding:
    """One finding as it appears in an engagement report."""

    title: str
    severity: Severity
    affected: str
    description: str
    remediation: str
    impact: str = ""
    cvss: str = ""
    steps: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    @classmethod
    def from_finding(cls, f: Finding) -> ReportFinding:
        """Adapt a scanner :class:`Finding` into a report finding."""
        return cls(
            title=f.title,
            severity=f.severity,
            affected=f.location.resource or f.location.path,
            description=f.description,
            remediation=f.remediation,
            impact="",
            steps=[f.evidence] if f.evidence else [],
            references=list(f.references),
        )


@dataclass
class Engagement:
    """Report metadata plus its findings."""

    client: str
    tester: str
    scope_summary: str
    date: str = ""
    findings: list[ReportFinding] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.date:
            object.__setattr__(self, "date", datetime.now(UTC).strftime("%Y-%m-%d"))


def _counts(findings: list[ReportFinding]) -> dict[Severity, int]:
    counts = dict.fromkeys(Severity, 0)
    for f in findings:
        counts[f.severity] += 1
    return counts


def render_markdown(engagement: Engagement) -> str:
    """Render a full engagement report as Markdown."""
    findings = sorted(engagement.findings, key=lambda f: (_SEV_ORDER[f.severity], f.title))
    counts = _counts(findings)
    summary_line = (
        ", ".join(f"{counts[s]} {s.value}" for s in Severity if counts[s]) or "no findings"
    )

    lines: list[str] = []
    lines.append(f"# Penetration Test Report — {engagement.client}")
    lines.append("")
    lines.append(f"**Tester:** {engagement.tester}  ")
    lines.append(f"**Date:** {engagement.date}  ")
    lines.append(f"**Scope:** {engagement.scope_summary}")
    lines.append("")

    lines.append("## Executive summary")
    lines.append("")
    lines.append(
        f"This assessment identified **{len(findings)}** finding(s): {summary_line}. "
        "Each is detailed below with its impact and recommended remediation, ordered "
        "by severity."
    )
    lines.append("")

    # Findings-at-a-glance table.
    lines.append("| # | Severity | Finding | Affected |")
    lines.append("|---|----------|---------|----------|")
    for i, f in enumerate(findings, 1):
        lines.append(f"| {i} | {f.severity.value.upper()} | {f.title} | {f.affected} |")
    lines.append("")

    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "Testing followed a standard methodology — reconnaissance, enumeration, "
        "exploitation, and post-exploitation — conducted strictly within the "
        "authorized scope, with evidence captured throughout."
    )
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    for i, f in enumerate(findings, 1):
        lines.append(f"### {i}. {f.title}")
        lines.append("")
        lines.append(
            f"- **Severity:** {f.severity.value.upper()}" + (f" (CVSS {f.cvss})" if f.cvss else "")
        )
        lines.append(f"- **Affected:** {f.affected}")
        lines.append("")
        lines.append(f"**Description.** {f.description}")
        lines.append("")
        if f.impact:
            lines.append(f"**Impact.** {f.impact}")
            lines.append("")
        if f.steps:
            lines.append("**Reproduction steps.**")
            lines.append("")
            for n, step in enumerate(f.steps, 1):
                lines.append(f"{n}. {step}")
            lines.append("")
        lines.append(f"**Remediation.** {f.remediation}")
        lines.append("")
        if f.references:
            lines.append("**References.**")
            for ref in f.references:
                lines.append(f"- {ref}")
            lines.append("")

    lines.append("## Appendix")
    lines.append("")
    lines.append(
        "Testing was authorized and conducted within the agreed scope. This report "
        "is confidential and intended for the client named above."
    )
    lines.append("")
    return "\n".join(lines)


def _finding_from_dict(data: dict[str, Any]) -> ReportFinding:
    try:
        severity = Severity(str(data.get("severity", "medium")).lower())
    except ValueError:
        severity = Severity.MEDIUM
    return ReportFinding(
        title=str(data.get("title", "Untitled finding")),
        severity=severity,
        affected=str(data.get("affected", "unspecified")),
        description=str(data.get("description", "")),
        remediation=str(data.get("remediation", "")),
        impact=str(data.get("impact", "")),
        cvss=str(data.get("cvss", "")),
        steps=[str(s) for s in (data.get("steps") or [])],
        references=[str(r) for r in (data.get("references") or [])],
    )


def engagement_from_dict(data: dict[str, Any]) -> Engagement:
    """Build an :class:`Engagement` from a parsed engagement file."""
    meta = data.get("engagement")
    if not isinstance(meta, dict):
        raise ValueError("engagement file must contain an 'engagement' mapping.")
    findings = [_finding_from_dict(f) for f in (data.get("findings") or []) if isinstance(f, dict)]
    return Engagement(
        client=str(meta.get("client", "Client")),
        tester=str(meta.get("tester", "")),
        scope_summary=str(meta.get("scope", "")),
        date=str(meta.get("date", "")),
        findings=findings,
    )
