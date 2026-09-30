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

from cloudnova import service
from cloudnova.core.baseline import Baseline
from cloudnova.core.check import registry
from cloudnova.core.engine import Engine, ScanResult, filter_by_severity
from cloudnova.core.findings import Severity
from cloudnova.diff import diff_reports
from cloudnova.graph import build_graph, find_attack_paths
from cloudnova.graph.attack_paths import paths_to_findings
from cloudnova.iam import GenerationError, analyze_policy, generate_policy
from cloudnova.range import (
    ReconParseError,
    Scope,
    ScopeError,
    active_persona,
    engagement_from_dict,
    list_personas,
    load_scope,
    mentor,
    organize,
    render_markdown,
    set_active,
)
from cloudnova.reporting import render_console, render_html, render_json, render_sarif
from cloudnova.triage import triage_findings

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
def triage(
    path: Annotated[Path, typer.Argument(help="File or directory to scan and triage.")],
    limit: Annotated[
        int, typer.Option("--limit", "-n", help="How many top findings to explain.")
    ] = 5,
    min_severity: Annotated[
        str | None,
        typer.Option("--min-severity", help="Only triage findings at/above this severity."),
    ] = None,
) -> None:
    """Scan, then explain the worst findings in plain English with concrete fixes.

    Uses Claude when ANTHROPIC_API_KEY is set (install `cloudnova[agent]`); otherwise
    gives a useful offline explanation built from each finding and its ATT&CK mapping.
    """
    if not path.exists():
        _console.print(f"[red]Path not found: {path}[/]")
        raise typer.Exit(code=2)
    result = service.scan(str(path), min_severity=min_severity)
    findings = result["findings"]
    if not findings:
        _console.print("No findings to triage. 🎉")
        return
    notes = triage_findings(findings, limit=limit)
    for i, note in enumerate(notes, 1):
        _console.print(
            f"\n[bold]{i}. [{note.severity.upper()}] {note.title}[/] "
            f"[dim]({note.check_id}, via {note.source})[/]"
        )
        _console.print(note.text)
    shown = len(notes)
    if len(findings) > shown:
        _console.print(
            f"\n[dim]… {len(findings) - shown} more finding(s). Raise --limit to see them.[/]"
        )


@app.command()
def diff(
    old_report: Annotated[
        Path, typer.Argument(help="Previous scan JSON (from `scan --format json`).")
    ],
    path: Annotated[Path, typer.Argument(help="Current file or directory to scan and compare.")],
    fail_on_new: Annotated[
        bool, typer.Option("--fail-on-new", help="Exit non-zero if any new finding was introduced.")
    ] = False,
) -> None:
    """Show what changed vs a previous scan: newly introduced and fixed findings."""
    if not old_report.exists():
        _console.print(f"[red]Old report not found: {old_report}[/]")
        raise typer.Exit(code=2)
    if not path.exists():
        _console.print(f"[red]Path not found: {path}[/]")
        raise typer.Exit(code=2)
    try:
        old = json.loads(old_report.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _console.print(f"[red]Could not parse {old_report}: {exc}[/]")
        raise typer.Exit(code=2) from exc
    new = service.scan(str(path))
    delta = diff_reports(old, new)

    if delta.introduced:
        _console.print(f"[bold red]Introduced ({len(delta.introduced)}):[/]")
        for f in delta.introduced:
            loc = f["location"].get("resource") or f["location"]["path"]
            _console.print(f"  [red]+[/] [{f['severity'].upper()}] {f['title']} — {loc}")
    if delta.fixed:
        _console.print(f"[bold green]Fixed ({len(delta.fixed)}):[/]")
        for f in delta.fixed:
            loc = f["location"].get("resource") or f["location"]["path"]
            _console.print(f"  [green]-[/] [{f['severity'].upper()}] {f['title']} — {loc}")
    if not delta.introduced and not delta.fixed:
        _console.print("No change in findings.")

    arrow = (
        "▲ worse"
        if delta.score_delta > 0
        else ("▼ better" if delta.score_delta < 0 else "no change")
    )
    _console.print(
        f"\nPosture: {delta.old_score} → {delta.new_score} "
        f"([bold]{delta.score_delta:+d}[/], {arrow}) · {delta.unchanged} unchanged."
    )
    if fail_on_new and delta.introduced:
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


# ---- iam subcommands: author and audit IAM policies ----
iam_app = typer.Typer(help="Author and audit IAM policies.", no_args_is_help=True)
app.add_typer(iam_app, name="iam")


# ---- cloud subcommands: live read-only account scanning ----
cloud_app = typer.Typer(
    help="Scan a LIVE cloud account (read-only) with your own credentials.",
    no_args_is_help=True,
)
app.add_typer(cloud_app, name="cloud")


def _print_findings(findings: list, target: str) -> None:  # type: ignore[type-arg]
    if not findings:
        _console.print(f"[green]No findings[/] for {target}.")
        return
    colors = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
    _console.print(f"[bold]Live scan:[/] {target} — {len(findings)} findings\n")
    for f in findings:
        color = colors.get(f.severity.value, "white")
        _console.print(f"[{color}]{f.severity.value.upper():8}[/] {f.check_id}  {f.title}")
        _console.print(f"         [dim]{f.location.path}[/]")
        _console.print(f"         [dim]{f.description}[/]\n")


@cloud_app.command("aws")
def cloud_aws(
    profile: Annotated[str, typer.Option("--profile", help="AWS profile name.")] = "",
    region: Annotated[str, typer.Option("--region", help="AWS region.")] = "",
) -> None:
    """Scan a live AWS account read-only (needs the 'aws' extra + credentials)."""
    try:
        from cloudnova.cloud import scan_aws
    except ImportError:
        _console.print('[red]Install the AWS extra:[/] pip install -e ".[aws]"')
        raise typer.Exit(code=2) from None
    try:
        findings = scan_aws(profile=profile or None, region=region or None)
    except Exception as exc:
        _console.print(f"[red]AWS scan failed:[/] {exc}")
        raise typer.Exit(code=1) from None
    _print_findings(findings, "AWS account")


@cloud_app.command("azure")
def cloud_azure(
    subscription: Annotated[
        str, typer.Option("--subscription", help="Azure subscription id.")
    ] = "",
) -> None:
    """Scan a live Azure subscription read-only (needs the 'azure' extra + credentials)."""
    try:
        from cloudnova.cloud import scan_azure
    except ImportError:
        _console.print('[red]Install the Azure extra:[/] pip install -e ".[azure]"')
        raise typer.Exit(code=2) from None
    try:
        findings = scan_azure(subscription_id=subscription or None)
    except Exception as exc:
        _console.print(f"[red]Azure scan failed:[/] {exc}")
        raise typer.Exit(code=1) from None
    _print_findings(findings, "Azure subscription")


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


@range_app.command("whoami")
def range_whoami() -> None:
    """Show the active operator persona."""
    p = active_persona()
    _console.print(f"[bold cyan]{p.display_name}[/]  [dim](persona: {p.id})[/]")
    _console.print(f"  handle:  {p.handle}")
    _console.print(f"  {p.tagline}")


persona_app = typer.Typer(help="Switch the operator persona (cosmetic only).", no_args_is_help=True)
range_app.add_typer(persona_app, name="persona")


@persona_app.command("list")
def persona_list() -> None:
    """List available personas."""
    active = active_persona().id
    for p in list_personas():
        mark = "[green]*[/]" if p.id == active else " "
        _console.print(f"{mark} [bold]{p.id}[/] — {p.display_name}: {p.tagline}")


@persona_app.command("use")
def persona_use(
    persona_id: Annotated[str, typer.Argument(help="Persona id: cloudnova or gh0st.")],
) -> None:
    """Switch the active persona (saved to your config)."""
    try:
        p = set_active(persona_id)
    except KeyError as exc:
        _console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=2) from exc
    _console.print(f"Persona set to [bold cyan]{p.display_name}[/] ({p.id}). {p.banner()}")


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


@range_app.command("webassess")
def range_webassess(
    url: Annotated[str, typer.Argument(help="Target URL (http/https) to assess.")],
    scope_file: Annotated[
        Path, typer.Option("--scope", "-s", help="Scope file (YAML) declaring authorized targets.")
    ],
    no_paths: Annotated[
        bool, typer.Option("--no-paths", help="Skip the sensitive-path check.")
    ] = False,
) -> None:
    """Passive, authorized web posture assessment — scope-gated and non-destructive.

    Makes benign read-only requests to an in-scope target and reports missing
    security headers, weak cookies, permissive CORS, plaintext transport, version
    disclosure, and reachable sensitive paths. Never sends payloads or exploits.
    """
    from cloudnova.range.webassess import assess

    scope = _load_scope_or_exit(scope_file)
    result = assess(url, scope, check_paths=not no_paths)
    if not result.authorized:
        _console.print(f"[red]DENY[/] {result.target} — {result.reason}")
        raise typer.Exit(code=1)
    if not result.findings:
        _console.print(f"[green]No passive findings[/] for {result.target}. ({result.reason})")
        return
    _colors = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
    _console.print(f"[bold]Web assessment:[/] {result.target}\n")
    for finding in result.findings:
        color = _colors.get(finding.severity.value, "white")
        _console.print(
            f"[{color}]{finding.severity.value.upper():8}[/] {finding.id}  {finding.title}"
        )
        _console.print(f"         [dim]{finding.detail}[/]")
        _console.print(f"         [dim]fix:[/] {finding.remediation}\n")


@range_app.command("checklist")
def range_checklist(
    url: Annotated[str, typer.Argument(help="Target URL (http/https) to assess.")],
    scope_file: Annotated[
        Path | None,
        typer.Option("--scope", "-s", help="Scope file (YAML) declaring authorized targets."),
    ] = None,
    i_am_authorized: Annotated[
        str,
        typer.Option(
            "--i-am-authorized",
            help="No scope file: attest you own/are authorized to test this target "
            "(pass your name). Recorded in the report as your responsibility.",
        ),
    ] = "",
    active: Annotated[
        bool,
        typer.Option("--active", help="Opt in to intrusive DETECTION (XSS/SQLi/traversal)."),
    ] = False,
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Write the full report (Markdown) here.")
    ] = None,
) -> None:
    """Run the blackbox pentest checklist (PTES + OWASP WSTG) against an authorized target.

    Passive items run automatically; --active opts in to non-destructive intrusive
    detection; manual items are tracked with methodology. Either pass a --scope file
    or self-attest authorization with --i-am-authorized "<your name>".
    """
    from cloudnova.range.checklist import render_report, run_checklist
    from cloudnova.range.checklist.report import render_summary_line
    from cloudnova.range.scope import self_authorized_scope

    if scope_file is not None:
        scope = _load_scope_or_exit(scope_file)
    elif i_am_authorized.strip():
        scope = self_authorized_scope(url, i_am_authorized.strip())
        _console.print(
            f"[yellow]Self-authorized[/] by {i_am_authorized.strip()} — you accept "
            "responsibility for testing this target."
        )
    else:
        _console.print('[red]Refusing:[/] provide --scope FILE or --i-am-authorized "<name>".')
        raise typer.Exit(code=2)

    run = run_checklist(url, scope, active=active)
    if not run.authorized:
        _console.print(f"[red]DENY[/] {run.target} — {run.attestation}")
        raise typer.Exit(code=1)

    _console.print(f"[bold]Checklist:[/] {render_summary_line(run)}\n")
    _colors = {"FAIL": "red", "PASS": "green", "TODO": "yellow", "N/A": "dim", "INFO": "cyan"}
    for ri in run.items:
        color = _colors.get(ri.state.value, "white")
        _console.print(f"[{color}]{ri.state.value:5}[/] {ri.item.id:9} {ri.item.test_case}")
    if out is not None:
        out.write_text(render_report(run), encoding="utf-8")
        _console.print(f"\n[green]Report written[/] to {out}")


# ---- tool subcommands: orchestrate real tools (scope-gated) ----
tool_app = typer.Typer(
    help="Run real tools (nmap/nuclei/ffuf) against authorized targets, output as findings.",
    no_args_is_help=True,
)
range_app.add_typer(tool_app, name="tool")


def _tool_scope(target: str, scope_file: Path | None, i_am_authorized: str) -> Scope:
    from cloudnova.range.scope import self_authorized_scope

    if scope_file is not None:
        return _load_scope_or_exit(scope_file)
    if i_am_authorized.strip():
        _console.print(
            f"[yellow]Self-authorized[/] by {i_am_authorized.strip()} — you accept responsibility."
        )
        return self_authorized_scope(target, i_am_authorized.strip())
    _console.print('[red]Refusing:[/] provide --scope FILE or --i-am-authorized "<name>".')
    raise typer.Exit(code=2)


def _emit_tool_result(result: object) -> None:
    r = result  # ToolResult
    if not r.ran:  # type: ignore[attr-defined]
        _console.print(f"[yellow]Not run:[/] {r.note}")  # type: ignore[attr-defined]
        raise typer.Exit(code=1)
    _print_findings(r.findings, r.target)  # type: ignore[attr-defined]


@tool_app.command("nmap")
def tool_nmap(
    target: Annotated[str, typer.Argument(help="Host/IP to scan.")],
    scope_file: Annotated[Path | None, typer.Option("--scope", "-s")] = None,
    i_am_authorized: Annotated[str, typer.Option("--i-am-authorized")] = "",
    full: Annotated[bool, typer.Option("--full", help="All ports (-p-), slower.")] = False,
) -> None:
    """Run nmap service discovery against an authorized host."""
    from cloudnova.range.toolkit import nmap

    scope = _tool_scope(target, scope_file, i_am_authorized)
    _emit_tool_result(nmap.run(target, scope, full=full))


@tool_app.command("nuclei")
def tool_nuclei(
    url: Annotated[str, typer.Argument(help="URL to scan.")],
    scope_file: Annotated[Path | None, typer.Option("--scope", "-s")] = None,
    i_am_authorized: Annotated[str, typer.Option("--i-am-authorized")] = "",
) -> None:
    """Run nuclei template checks against an authorized URL."""
    from cloudnova.range.toolkit import nuclei

    scope = _tool_scope(url, scope_file, i_am_authorized)
    _emit_tool_result(nuclei.run(url, scope))


@tool_app.command("ffuf")
def tool_ffuf(
    url: Annotated[str, typer.Argument(help="URL containing FUZZ, e.g. https://t/FUZZ")],
    wordlist: Annotated[Path, typer.Option("--wordlist", "-w", help="Wordlist file.")],
    scope_file: Annotated[Path | None, typer.Option("--scope", "-s")] = None,
    i_am_authorized: Annotated[str, typer.Option("--i-am-authorized")] = "",
) -> None:
    """Run ffuf content discovery against an authorized URL."""
    from cloudnova.range.toolkit import ffuf

    scope = _tool_scope(url, scope_file, i_am_authorized)
    _emit_tool_result(ffuf.run(url, scope, wordlist=str(wordlist)))


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


@mentor_app.command("done")
def mentor_done(
    module_id: Annotated[
        str, typer.Argument(help="Module id you've completed (see `mentor path`).")
    ],
) -> None:
    """Mark a curriculum module as completed."""
    try:
        module = mentor.mark_done(module_id)
    except KeyError:
        ids = ", ".join(m.id for m in mentor.all_modules())
        _console.print(f"[red]Unknown module {module_id!r}. Available: {ids}[/]")
        raise typer.Exit(code=2) from None
    prog = mentor.summary()
    _console.print(
        f"[green]✓[/] Marked [bold]{module.title}[/] done. "
        f"Progress: {prog.done}/{prog.total} ({prog.percent}%)."
    )


@mentor_app.command("undone")
def mentor_undone(
    module_id: Annotated[str, typer.Argument(help="Module id to un-mark (see `mentor progress`).")],
) -> None:
    """Un-mark a curriculum module (undo a `mentor done`)."""
    mentor.mark_undone(module_id)
    prog = mentor.summary()
    _console.print(
        f"[yellow]○[/] Un-marked [bold]{module_id}[/]. "
        f"Progress: {prog.done}/{prog.total} ({prog.percent}%)."
    )


@mentor_app.command("progress")
def mentor_progress() -> None:
    """Show your progress and what's next."""
    prog = mentor.summary()
    done = mentor.completed()
    _console.print(f"[bold]Progress:[/] {prog.done}/{prog.total} ({prog.percent}%)\n")
    for step in mentor.learning_path():
        mark = "[green]✓[/]" if step.module.id in done else "[dim]○[/]"
        _console.print(f"  {mark} {step.module.title} [dim]({step.module.id})[/]")
    nxt = mentor.next_modules(1)
    if nxt:
        _console.print(
            f"\n[bold]Next up:[/] {nxt[0].title} — `cloudnova range mentor topic {nxt[0].id}`"
        )
    else:
        _console.print("\n[green]All modules complete. 🎓[/]")


@mentor_app.command("next")
def mentor_next(
    count: Annotated[int, typer.Option("--count", "-n", help="How many next steps to show.")] = 3,
) -> None:
    """Show the next module(s) to study, based on your progress."""
    nxt = mentor.next_modules(count)
    if not nxt:
        _console.print("[green]All caught up — every module is complete. 🎓[/]")
        return
    for m in nxt:
        _print_module(m)
        _console.print(f"   [dim]→ cloudnova range mentor topic {m.id}[/]")


@mentor_app.command("ask")
def mentor_ask(
    question: Annotated[str, typer.Argument(help="Ask your pentest mentor anything.")],
) -> None:
    """Ask the mentor a question (Claude-powered when an API key is set, offline otherwise)."""
    answer = mentor.ask(question)
    _console.print(answer.text)
    if answer.source == "offline":
        _console.print(
            "\n[dim]Tip: set ANTHROPIC_API_KEY and install `cloudnova[agent]` for full "
            "Claude-powered mentoring.[/]"
        )


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
    # Default the report byline to the active operator persona when unspecified.
    if not engagement.tester:
        engagement.tester = active_persona().handle
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
