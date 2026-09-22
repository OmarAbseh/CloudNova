"""CloudNova command-line interface.

    cloudnova scan <path>              # scan a file or directory
    cloudnova scan . --format json     # machine-readable output
    cloudnova scan . --fail-on high    # non-zero exit for CI gating
    cloudnova checks                   # list the loaded ruleset

The ``--fail-on`` flag is what makes CloudNova usable as a pipeline gate: it
sets the process exit code when findings at or above a severity exist, so a CI
job fails the build on real risk.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from cloudnova.core.baseline import Baseline
from cloudnova.core.check import registry
from cloudnova.core.engine import Engine, filter_by_severity
from cloudnova.core.findings import Severity
from cloudnova.graph import build_graph, find_attack_paths
from cloudnova.graph.attack_paths import paths_to_findings
from cloudnova.reporting import render_console, render_html, render_json, render_sarif

app = typer.Typer(
    add_completion=False,
    help="CloudNova — cloud security scanning engine.",
    no_args_is_help=True,
)
_console = Console()


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="File or directory to scan.")],
    output_format: Annotated[
        str, typer.Option("--format", "-f", help="Output format: table, json, sarif, or html.")
    ] = "table",
    fail_on: Annotated[
        str | None,
        typer.Option("--fail-on", help="Exit non-zero if a finding at/above this severity exists."),
    ] = None,
    baseline: Annotated[
        Path | None,
        typer.Option("--baseline", help="Suppress findings recorded in this baseline file."),
    ] = None,
    graph: Annotated[
        bool,
        typer.Option("--graph/--no-graph", help="Analyze cross-resource attack paths."),
    ] = True,
    min_severity: Annotated[
        str | None,
        typer.Option("--min-severity", help="Only report findings at/above this severity."),
    ] = None,
) -> None:
    """Scan PATH for security findings."""
    if not path.exists():
        _console.print(f"[red]Path not found: {path}[/]")
        raise typer.Exit(code=2)

    result = Engine().scan_path(path)

    if graph and result.resources:
        # Cross-file analysis: build the resource graph and add attack-path findings.
        resource_graph = build_graph(result.resources)
        result.findings.extend(paths_to_findings(resource_graph, find_attack_paths(resource_graph)))

    if baseline is not None:
        if not baseline.exists():
            _console.print(f"[red]Baseline file not found: {baseline}[/]")
            raise typer.Exit(code=2)
        result = Baseline.load(baseline).filter(result)

    if min_severity is not None:
        threshold = _parse_severity(min_severity)
        result = filter_by_severity(result, threshold)

    if output_format == "json":
        # Plain print (not Rich) so the JSON is pipeable and unstyled.
        print(render_json(result))
    elif output_format == "sarif":
        print(render_sarif(result))
    elif output_format == "html":
        print(render_html(result))
    elif output_format == "table":
        render_console(result, _console)
    else:
        _console.print(
            f"[red]Unknown format: {output_format!r} (use table, json, sarif, or html).[/]"
        )
        raise typer.Exit(code=2)

    if fail_on:
        threshold = _parse_severity(fail_on)
        if any(f.severity.rank >= threshold.rank for f in result.findings):
            raise typer.Exit(code=1)


@app.command()
def baseline(
    path: Annotated[Path, typer.Argument(help="File or directory to scan.")],
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Where to write the baseline file.")
    ] = Path(".cloudnova-baseline.json"),
) -> None:
    """Record all current findings as an accepted baseline.

    Later runs of ``scan --baseline <file>`` report only findings introduced
    after this snapshot.
    """
    if not path.exists():
        _console.print(f"[red]Path not found: {path}[/]")
        raise typer.Exit(code=2)
    result = Engine().scan_path(path)
    Baseline.from_result(result).save(output)
    _console.print(
        f"Wrote baseline with [bold]{len(result.findings)}[/] finding(s) to [bold]{output}[/]."
    )


@app.command()
def checks() -> None:
    """List every loaded check in the ruleset."""
    table = Table(title=f"CloudNova ruleset — {len(registry)} checks")
    table.add_column("ID", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Target", no_wrap=True)
    table.add_column("Title")
    for check in sorted(registry.all(), key=lambda c: (-c.severity.rank, c.id)):
        table.add_row(check.id, check.severity.value, check.target, check.title)
    _console.print(table)


def _parse_severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError as exc:
        valid = ", ".join(s.value for s in Severity)
        _console.print(f"[red]Invalid severity {value!r}. Choose from: {valid}.[/]")
        raise typer.Exit(code=2) from exc


if __name__ == "__main__":
    app()
