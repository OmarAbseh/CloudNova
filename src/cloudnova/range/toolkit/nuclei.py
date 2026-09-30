"""nuclei adapter: template-based checks (JSONL) -> Findings."""

from __future__ import annotations

import json

from cloudnova.core.findings import Confidence, Finding, Location, Severity
from cloudnova.range.scope import Scope
from cloudnova.range.toolkit.base import Runner, ToolResult, ToolTier, execute

BINARY = "nuclei"

_SEV = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


def build_argv(url: str) -> list[str]:
    return ["nuclei", "-u", url, "-jsonl", "-silent"]


def parse(stdout: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = row.get("info", {})
        sev = _SEV.get(str(info.get("severity", "info")).lower(), Severity.INFO)
        template = row.get("template-id", row.get("templateID", "nuclei"))
        matched = row.get("matched-at", row.get("host", ""))
        findings.append(
            Finding(
                check_id=f"NUCLEI_{str(template).upper().replace('-', '_')}"[:60],
                title=str(info.get("name", template)),
                severity=sev,
                confidence=Confidence.MEDIUM,
                location=Location(path=str(matched) or "n/a"),
                description=str(info.get("description", "") or info.get("name", template)),
                remediation=str(
                    info.get("remediation", "") or "Review the nuclei template guidance."
                ),
                references=list(info.get("reference", []) or []),
            )
        )
    return findings


def run(
    url: str, scope: Scope, *, runner: Runner | None = None, timeout: float = 900.0
) -> ToolResult:
    return execute(
        tool="nuclei",
        binary=BINARY,
        tier=ToolTier.ACTIVE,
        target=url,
        scope=scope,
        argv=build_argv(url),
        parser=parse,
        runner=runner,
        timeout=timeout,
    )
