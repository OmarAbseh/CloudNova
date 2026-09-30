"""ffuf adapter: content discovery (JSON) -> Findings."""

from __future__ import annotations

import json

from cloudnova.core.findings import Confidence, Finding, Location, Severity
from cloudnova.range.scope import Scope
from cloudnova.range.toolkit.base import Runner, ToolResult, ToolTier, execute

BINARY = "ffuf"


def build_argv(
    url: str, wordlist: str, *, match_codes: str = "200,204,301,302,401,403"
) -> list[str]:
    # Caller supplies a URL containing FUZZ, e.g. https://t/FUZZ
    return ["ffuf", "-u", url, "-w", wordlist, "-mc", match_codes, "-of", "json", "-o", "-"]


def parse(stdout: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = json.loads(stdout) if stdout.strip() else {}
    except json.JSONDecodeError:
        return findings
    for res in data.get("results", []):
        url = res.get("url", "")
        status = res.get("status", 0)
        findings.append(
            Finding(
                check_id="FFUF_DISCOVERED_PATH",
                title=f"Discovered path (HTTP {status})",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                location=Location(path=str(url)),
                description=f"Content discovery found {url} returning HTTP {status}.",
                remediation="Review whether this path should be publicly reachable.",
                evidence=f"status={status} length={res.get('length', '?')}",
            )
        )
    return findings


def run(
    url: str,
    scope: Scope,
    *,
    wordlist: str,
    runner: Runner | None = None,
    timeout: float = 900.0,
) -> ToolResult:
    return execute(
        tool="ffuf",
        binary=BINARY,
        tier=ToolTier.ACTIVE,
        target=url,
        scope=scope,
        argv=build_argv(url, wordlist),
        parser=parse,
        runner=runner,
        timeout=timeout,
    )
