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

from cloudnova.core.check import registry
from cloudnova.core.engine import Engine
from cloudnova.core.findings import Severity
from cloudnova.reporting import render_console, render_json

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
        str, typer.Option("--format", "-f", help="Output format: table or json.")
    ] = "table",
    fail_on: Annotated[
        str | None,
        typer.Option("--fail-on", help="Exit non-zero if a finding at/above this severity exists."),
    ] = None,
) -> None:
    """Scan PATH for security findings."""
    if not path.exists():
        _console.print(f"[red]Path not found: {path}[/]")
        raise typer.Exit(code=2)

    result = Engine().scan_path(path)

    if output_format == "json":
        # Plain print (not Rich) so the JSON is pipeable and unstyled.
        print(render_json(result))
    elif output_format == "table":
        render_console(result, _console)
    else:
        _console.print(f"[red]Unknown format: {output_format!r} (use 'table' or 'json').[/]")
        raise typer.Exit(code=2)

    if fail_on:
        threshold = _parse_severity(fail_on)
        if any(f.severity.rank >= threshold.rank for f in result.findings):
            raise typer.Exit(code=1)


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
