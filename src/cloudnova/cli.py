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

import json
from pathlib import Path
from typing import Annotated

import typer
import yaml
from rich.console import Console
from rich.table import Table

from cloudnova.core.baseline import Baseline
from cloudnova.core.check import registry
from cloudnova.core.engine import Engine, ScanResult, filter_by_severity
from cloudnova.core.findings import Severity
from cloudnova.graph import build_graph, find_attack_paths
from cloudnova.graph.attack_paths import paths_to_findings
from cloudnova.iam import GenerationError, analyze_policy, generate_policy
from cloudnova.range import (
    ReconParseError,
    Scope,
    ScopeError,
    engagement_from_dict,
    load_scope,
    mentor,
    organize,
    render_markdown,
)
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


# ---- iam subcommands: author and audit IAM policies ----
iam_app = typer.Typer(help="Author and audit IAM policies.", no_args_is_help=True)
app.add_typer(iam_app, name="iam")


def _load_structured(path: Path) -> object:
    """Load a JSON or YAML file into Python data."""
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        return yaml.safe_load(text)
    return json.loads(text)


@iam_app.command("generate")
def iam_generate(
    spec: Annotated[Path, typer.Argument(help="Grant-spec file (JSON or YAML).")],
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the policy here instead of stdout.")
    ] = None,
) -> None:
    """Generate a least-privilege IAM policy from a grant spec."""
    if not spec.exists():
        _console.print(f"[red]Spec not found: {spec}[/]")
        raise typer.Exit(code=2)
    try:
        data = _load_structured(spec)
        if not isinstance(data, dict):
            raise GenerationError("spec must be a mapping with a 'grants' list.")
        policy = generate_policy(data)
    except (GenerationError, json.JSONDecodeError, yaml.YAMLError) as exc:
        _console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=2) from exc
    rendered = json.dumps(policy, indent=2)
    if output is not None:
        output.write_text(rendered + "\n", encoding="utf-8")
        _console.print(f"Wrote least-privilege policy to [bold]{output}[/].")
    else:
        print(rendered)


@iam_app.command("analyze")
def iam_analyze(
    policy: Annotated[Path, typer.Argument(help="IAM policy document (JSON or YAML).")],
    output_format: Annotated[
        str, typer.Option("--format", "-f", help="Output format: table or json.")
    ] = "table",
) -> None:
    """Analyze an IAM policy for anti-patterns and privilege escalation."""
    if not policy.exists():
        _console.print(f"[red]Policy not found: {policy}[/]")
        raise typer.Exit(code=2)
    try:
        doc = _load_structured(policy)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        _console.print(f"[red]Could not parse {policy}: {exc}[/]")
        raise typer.Exit(code=2) from exc

    findings = analyze_policy(doc, source=str(policy))
    result = ScanResult(findings=findings, files_scanned=1, checks_run=1)
    if output_format == "json":
        print(render_json(result))
    else:
        render_console(result, _console)


# ---- range subcommands: authorized security testing (authorization-first) ----
range_app = typer.Typer(
    help="CloudNova Range — authorized testing. Everything gates through the scope engine.",
    no_args_is_help=True,
)
app.add_typer(range_app, name="range")


def _load_scope_or_exit(scope_path: Path) -> Scope:
    if not scope_path.exists():
        _console.print(f"[red]Scope file not found: {scope_path}[/]")
        raise typer.Exit(code=2)
    try:
        return load_scope(scope_path)
    except ScopeError as exc:
        _console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=2) from exc


@range_app.command("scope")
def range_scope(
    scope_file: Annotated[
        Path, typer.Argument(help="Scope file (YAML) declaring authorized targets.")
    ],
) -> None:
    """Show a loaded scope and its authorization attestation."""
    scope = _load_scope_or_exit(scope_file)
    auth = scope.authorization
    status = "[green]valid[/]" if auth.is_valid() else "[red]INVALID (fails closed)[/]"
    _console.print(f"Authorization: {status}")
    _console.print(f"  program:       {auth.program or '[red]missing[/]'}")
    _console.print(f"  authorized_by: {auth.authorized_by or '[red]missing[/]'}")
    _console.print(f"  acknowledged:  {auth.acknowledged}")
    if auth.reference:
        _console.print(f"  reference:     {auth.reference}")
    _console.print(f"\nIn scope ([bold]{len(scope.in_scope)}[/]):")
    for entry in scope.in_scope:
        _console.print(f"  [green]+[/] {entry}")
    if scope.out_of_scope:
        _console.print(f"Out of scope ([bold]{len(scope.out_of_scope)}[/], exclusions win):")
        for entry in scope.out_of_scope:
            _console.print(f"  [red]-[/] {entry}")


@range_app.command("check")
def range_check(
    target: Annotated[str, typer.Argument(help="Target to authorize (IP, domain, account id).")],
    scope_file: Annotated[
        Path, typer.Option("--scope", "-s", help="Scope file (YAML) declaring authorized targets.")
    ],
) -> None:
    """Check whether a target is authorized for testing (deny by default).

    Exit code 0 if ALLOWED, 1 if DENIED — so scripts can gate on it.
    """
    scope = _load_scope_or_exit(scope_file)
    decision = scope.authorize(target)
    if decision.allowed:
        _console.print(f"[green]ALLOW[/] {decision.target} — {decision.reason}")
    else:
        _console.print(f"[red]DENY[/] {decision.target} — {decision.reason}")
        raise typer.Exit(code=1)


# ---- mentor subcommands: the pentest tutor (learning is safe/ungated) ----
mentor_app = typer.Typer(
    help="CloudNova Mentor — your pentest tutor: learning paths, cert tracks, guided labs.",
    no_args_is_help=True,
)
range_app.add_typer(mentor_app, name="mentor")


def _print_module(module: mentor.Module, *, order: int | None = None) -> None:
    prefix = f"[bold]{order}.[/] " if order is not None else ""
    _console.print(
        f"{prefix}[bold cyan]{module.title}[/]  [dim]({module.level}, id={module.id})[/]"
    )
    _console.print(f"   {module.summary}")


@mentor_app.command("path")
def mentor_path(
    level: Annotated[
        str | None,
        typer.Option("--level", help="Cap the path: foundation, junior, intermediate, senior."),
    ] = None,
) -> None:
    """Show the ordered learning path (prerequisites first)."""
    cap = mentor.Level(level.lower()) if level else None
    for step in mentor.learning_path(cap):
        _print_module(step.module, order=step.order)


@mentor_app.command("topic")
def mentor_topic(
    module_id: Annotated[str, typer.Argument(help="Module id (see `mentor path`).")],
) -> None:
    """Explain one topic: concepts, tools, practice resources, and related certs."""
    module = mentor.get_module(module_id)
    if module is None:
        ids = ", ".join(m.id for m in mentor.all_modules())
        _console.print(f"[red]Unknown topic {module_id!r}. Available: {ids}[/]")
        raise typer.Exit(code=2)
    _print_module(module)
    _console.print("\n[bold]Key concepts:[/]")
    for c in module.concepts:
        _console.print(f"   • {c}")
    _console.print(f"\n[bold]Tools:[/] {', '.join(module.tools)}")
    _console.print("[bold]Practice & references:[/]")
    for r in module.resources:
        _console.print(f"   • {r.name} [dim]({r.kind})[/] — {r.url}")
    if module.certs:
        _console.print(f"[bold]Counts toward:[/] {', '.join(module.certs)}")


@mentor_app.command("cert")
def mentor_cert(
    name: Annotated[str, typer.Argument(help="Certification (e.g. OSCP, PNPT, eJPT, CEH, eWPT).")],
) -> None:
    """Show the prep track for a certification."""
    try:
        modules = mentor.cert_track(name)
    except KeyError as exc:
        _console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=2) from exc
    _console.print(f"[bold]Prep track — {name.upper()}[/] ({len(modules)} modules):\n")
    for i, m in enumerate(modules, 1):
        _print_module(m, order=i)


@mentor_app.command("jobs")
def mentor_jobs(
    level: Annotated[str, typer.Argument(help="Hiring level: junior, mid, or senior.")],
) -> None:
    """Show the skills a hiring level expects (your readiness map)."""
    try:
        modules = mentor.job_track(level)
    except KeyError as exc:
        _console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=2) from exc
    _console.print(f"[bold]{level.capitalize()} pentester — expected skills[/] ({len(modules)}):\n")
    for i, m in enumerate(modules, 1):
        _print_module(m, order=i)


@mentor_app.command("lab")
def mentor_lab(
    target: Annotated[str, typer.Argument(help="Practice target (must be in your scope file).")],
    scope_file: Annotated[
        Path, typer.Option("--scope", "-s", help="Scope file authorizing the practice target.")
    ],
) -> None:
    """Start a guided, methodology-driven lab session against an authorized practice target."""
    scope = _load_scope_or_exit(scope_file)
    plan = mentor.start_lab_session(target, scope)
    if not plan.authorized:
        _console.print(f"[red]DENY[/] {plan.target} — {plan.decision.reason}")
        _console.print(
            "[yellow]Add the target to your scope file only if you're authorized to test it.[/]"
        )
        raise typer.Exit(code=1)
    _console.print(f"[green]Authorized[/] — guided lab plan for [bold]{plan.target}[/]:\n")
    for phase, steps in plan.phases:
        _console.print(f"[bold cyan]{phase}[/]")
        for s in steps:
            _console.print(f"   • {s}")


@range_app.command("recon")
def range_recon(
    nmap_xml: Annotated[Path, typer.Argument(help="nmap -oX output file to organize.")],
    scope_file: Annotated[
        Path, typer.Option("--scope", "-s", help="Scope file — hosts are gated through it.")
    ],
) -> None:
    """Organize nmap output into a scope-checked service inventory with next-steps."""
    if not nmap_xml.exists():
        _console.print(f"[red]nmap output not found: {nmap_xml}[/]")
        raise typer.Exit(code=2)
    scope = _load_scope_or_exit(scope_file)
    try:
        inventory = organize(nmap_xml.read_text(encoding="utf-8"), scope)
    except ReconParseError as exc:
        _console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=2) from exc

    for host in inventory.in_scope_hosts:
        _console.print(f"\n[bold green]{host.address}[/] [dim](in scope)[/]")
        if not host.services:
            _console.print("   [dim]no open services in output[/]")
        for svc in host.services:
            banner = " ".join(x for x in (svc.product, svc.version) if x)
            _console.print(
                f"   [bold]{svc.port}/{svc.protocol}[/] {svc.name}"
                + (f" [dim]({banner})[/]" if banner else "")
            )
            _console.print(f"      ↳ {svc.hint}")
    for addr in inventory.skipped_out_of_scope:
        _console.print(f"[red]skipped (out of scope):[/] {addr}")
    _console.print(
        f"\n[bold]{len(inventory.in_scope_hosts)}[/] in-scope host(s), "
        f"[bold]{len(inventory.skipped_out_of_scope)}[/] skipped."
    )


@range_app.command("report")
def range_report(
    engagement_file: Annotated[
        Path, typer.Argument(help="Engagement file (YAML): metadata + findings.")
    ],
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the report here instead of stdout.")
    ] = None,
) -> None:
    """Generate a professional penetration-test report from an engagement file."""
    if not engagement_file.exists():
        _console.print(f"[red]Engagement file not found: {engagement_file}[/]")
        raise typer.Exit(code=2)
    try:
        data = yaml.safe_load(engagement_file.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("engagement file must be a mapping.")
        engagement = engagement_from_dict(data)
    except (yaml.YAMLError, ValueError) as exc:
        _console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=2) from exc
    report = render_markdown(engagement)
    if output is not None:
        output.write_text(report, encoding="utf-8")
        _console.print(
            f"Wrote report ([bold]{len(engagement.findings)}[/] findings) to [bold]{output}[/]."
        )
    else:
        print(report)


if __name__ == "__main__":
    app()
