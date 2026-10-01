"""Toolkit framework: run real pentest tools, scope-gated, parse output to Findings.

CloudNova does not reimplement nmap or nuclei - it *orchestrates* them. Every
adapter follows the same contract:

1. Authorize the target through the Range scope engine BEFORE running anything.
2. For AGGRESSIVE tools (brute force, exploitation), require explicit operator
   confirmation - they never run autonomously.
3. Shell out with a list argv (never a shell string), with a timeout.
4. Parse the tool's output into the shared ``Finding`` contract.

The subprocess runner is injected, so adapters are fully testable offline: tests
pass a fake runner that returns canned tool output and assert on the Findings.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import urlparse

from cloudnova.core.findings import Finding
from cloudnova.range.scope import Scope


class ToolTier(StrEnum):
    PASSIVE = "passive"  # read-only recon
    ACTIVE = "active"  # sends probes / scans (non-destructive detection)
    AGGRESSIVE = "aggressive"  # brute force / exploitation, needs confirmation


class ToolError(Exception):
    """Raised for a toolkit misuse (unknown tool, missing binary when required)."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str = ""


# A runner turns an argv + timeout into a CommandResult. Injected for testability.
Runner = Callable[[list[str], float], CommandResult]


@dataclass
class ToolResult:
    tool: str
    target: str
    ran: bool
    note: str = ""
    returncode: int | None = None
    findings: list[Finding] = field(default_factory=list)


def default_runner(argv: list[str], timeout: float) -> CommandResult:
    """Run a command with no shell, capturing output, bounded by a timeout."""
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    return CommandResult(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


def host_of(target: str) -> str:
    """Extract a host from a URL or return the bare host/IP unchanged."""
    if "://" in target:
        return urlparse(target).hostname or target
    # host[:port]/path -> host
    return target.split("/", 1)[0].split(":", 1)[0]


def is_installed(binary: str) -> bool:
    return shutil.which(binary) is not None


def execute(
    *,
    tool: str,
    binary: str,
    tier: ToolTier,
    target: str,
    scope: Scope,
    argv: list[str],
    parser: Callable[[str], list[Finding]],
    runner: Runner | None = None,
    confirm: bool = False,
    timeout: float = 900.0,
) -> ToolResult:
    """Shared adapter flow: authorize, gate aggressive tools, run, parse."""
    host = host_of(target)
    decision = scope.authorize(host)
    if not decision.allowed:
        return ToolResult(tool=tool, target=host, ran=False, note=f"DENIED: {decision.reason}")

    if tier is ToolTier.AGGRESSIVE and not confirm:
        return ToolResult(
            tool=tool,
            target=host,
            ran=False,
            note="AGGRESSIVE tool requires explicit confirmation (confirm=True / --confirm).",
        )

    run = runner or default_runner
    if runner is None and not is_installed(binary):
        return ToolResult(
            tool=tool, target=host, ran=False, note=f"'{binary}' not installed on this host."
        )

    try:
        result = run(argv, timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return ToolResult(tool=tool, target=host, ran=False, note=f"run failed: {exc}")

    findings = parser(result.stdout)
    findings.sort(key=lambda f: f.sort_key())
    return ToolResult(
        tool=tool, target=host, ran=True, returncode=result.returncode, findings=findings
    )
