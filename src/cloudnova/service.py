"""Programmatic API returning plain JSON-serializable dicts.

This is the seam between CloudNova's engine and any *caller* that isn't a human
at a terminal — most importantly the MCP server (so an AI agent can scan and
reason about infrastructure), but equally a web API or another Python program.

Keeping this logic here, returning dicts (never Rich/console output), means the
MCP adapter stays a thin, boring wrapper and everything interesting is unit-
tested without needing an MCP client.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cloudnova.core.baseline import Baseline
from cloudnova.core.check import registry
from cloudnova.core.engine import Engine, ScanResult, filter_by_severity
from cloudnova.core.findings import Finding, Severity
from cloudnova.graph import build_graph, find_attack_paths
from cloudnova.graph.attack_paths import paths_to_findings
from cloudnova.scoring import posture_score


def _finding_dict(finding: Finding) -> dict[str, Any]:
    return finding.model_dump(mode="json")


def _run_scan(path: Path, *, include_graph: bool) -> ScanResult:
    result = Engine().scan_path(path)
    if include_graph and result.resources:
        graph = build_graph(result.resources)
        result.findings.extend(paths_to_findings(graph, find_attack_paths(graph)))
    return result


def scan(
    path: str,
    *,
    min_severity: str | None = None,
    include_graph: bool = True,
    baseline_path: str | None = None,
) -> dict[str, Any]:
    """Scan a path and return findings plus a severity summary.

    Raises ``FileNotFoundError`` if the path doesn't exist so callers get a
    clear error rather than an empty result.
    """
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"Path not found: {path}")

    result = _run_scan(target, include_graph=include_graph)

    if baseline_path:
        result = Baseline.load(Path(baseline_path)).filter(result)
    if min_severity:
        result = filter_by_severity(result, Severity(min_severity.lower()))

    counts: dict[str, int] = {s.value: 0 for s in Severity}
    for f in result.findings:
        counts[f.severity.value] += 1

    score = posture_score(result)
    return {
        "summary": {
            "files_scanned": result.files_scanned,
            "checks_run": result.checks_run,
            "findings": len(result.findings),
            "severity_counts": counts,
            "posture_score": score.score,
            "grade": score.grade,
            "score_breakdown": score.breakdown,
            "errors": len(result.errors),
        },
        "findings": [_finding_dict(f) for f in result.sorted_findings()],
        "errors": result.errors,
    }


def list_checks() -> dict[str, Any]:
    """Return the full ruleset as data (id, title, severity, target)."""
    checks = sorted(registry.all(), key=lambda c: (-c.severity.rank, c.id))
    return {
        "count": len(checks),
        "checks": [
            {"id": c.id, "title": c.title, "severity": c.severity.value, "target": c.target}
            for c in checks
        ],
    }


def attack_paths(path: str) -> dict[str, Any]:
    """Return only the cross-resource attack paths found under ``path``."""
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"Path not found: {path}")
    result = Engine().scan_path(target)
    graph = build_graph(result.resources)
    paths = find_attack_paths(graph)
    return {
        "count": len(paths),
        "paths": [
            {"entry": p.entry, "target": p.target, "chain": list(p.nodes), "reason": p.reason}
            for p in paths
        ],
    }
