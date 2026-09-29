"""Human-readable console output using Rich.

Severity is colour-coded and findings are grouped most-severe-first. This is
what a developer sees when they run ``cloudnova scan .`` locally.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cloudnova.core.engine import ScanResult
from cloudnova.core.findings import Severity
from cloudnova.scoring import posture_score

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render_console(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()

    if not result.findings:
        console.print(
            Panel(
                Text("No findings. 🎉", style="bold green"),
                title="CloudNova",
                border_style="green",
            )
        )
    else:
        table = Table(title="CloudNova — Security Findings", show_lines=True, expand=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Check", no_wrap=True)
        table.add_column("Resource", overflow="fold")
        table.add_column("Finding", overflow="fold")

        for f in result.sorted_findings():
            sev = Text(f.severity.value.upper(), style=_SEVERITY_STYLE[f.severity])
            resource = f"{f.location.path}\n{f.location.resource or ''}".strip()
            body = Text(f.title, style="bold")
            body.append(f"\n{f.description}", style="")
            body.append(f"\n↳ Fix: {f.remediation}", style="green")
            table.add_row(sev, f"{f.check_id}\n({f.confidence.value})", resource, body)
        console.print(table)

    counts = _severity_counts(result)
    summary = "  ".join(f"{sev.value}={counts[sev]}" for sev in Severity if counts[sev])
    console.print(
        f"\nScanned [bold]{result.files_scanned}[/] file(s), ran "
        f"[bold]{result.checks_run}[/] check(s). "
        f"[bold]{len(result.findings)}[/] finding(s){'  ' + summary if summary else ''}."
    )
    score = posture_score(result)
    grade_style = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}[
        score.grade
    ]
    console.print(
        f"Security posture: [{grade_style}]{score.grade}[/] "
        f"([bold]{score.score}[/]/100, lower is better)."
    )
    for err in result.errors:
        console.print(f"[yellow]! {err}[/]")


def _severity_counts(result: ScanResult) -> dict[Severity, int]:
    counts = dict.fromkeys(Severity, 0)
    for f in result.findings:
        counts[f.severity] += 1
    return counts
