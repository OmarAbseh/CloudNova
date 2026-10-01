"""nmap adapter: service/port discovery -> Findings. Reuses the recon XML parser."""

from __future__ import annotations

from cloudnova.checks._aws import SENSITIVE_PORTS
from cloudnova.core.findings import Confidence, Finding, Location, Severity
from cloudnova.range.recon import parse_nmap_xml
from cloudnova.range.scope import Scope
from cloudnova.range.toolkit.base import Runner, ToolResult, ToolTier, execute

BINARY = "nmap"


def build_argv(target: str, *, full: bool = False) -> list[str]:
    argv = ["nmap", "-sV", "-oX", "-"]
    if full:
        argv += ["-p-", "-T4"]
    argv.append(target)
    return argv


def parse(stdout: str) -> list[Finding]:
    findings: list[Finding] = []
    if not stdout.strip():
        return findings
    for host, services in parse_nmap_xml(stdout).items():
        for svc in services:
            sensitive = svc.port in SENSITIVE_PORTS
            banner = f"{svc.name} {svc.product} {svc.version}".strip()
            findings.append(
                Finding(
                    check_id="NMAP_OPEN_PORT",
                    title=f"Open port {svc.port}/{svc.protocol} ({svc.name})",
                    severity=Severity.HIGH if sensitive else Severity.INFO,
                    confidence=Confidence.HIGH,
                    location=Location(path=f"{host}:{svc.port}", resource=host),
                    description=f"{host} exposes {svc.port}/{svc.protocol} - {banner or svc.name}."
                    + (f" ({SENSITIVE_PORTS[svc.port]} is sensitive)" if sensitive else ""),
                    remediation=svc.hint,
                    evidence=banner or None,
                )
            )
    return findings


def run(
    target: str,
    scope: Scope,
    *,
    full: bool = False,
    runner: Runner | None = None,
    timeout: float = 900.0,
) -> ToolResult:
    return execute(
        tool="nmap",
        binary=BINARY,
        tier=ToolTier.ACTIVE,
        target=target,
        scope=scope,
        argv=build_argv(host_only(target), full=full),
        parser=parse,
        runner=runner,
        timeout=timeout,
    )


def host_only(target: str) -> str:
    from cloudnova.range.toolkit.base import host_of

    return host_of(target)
