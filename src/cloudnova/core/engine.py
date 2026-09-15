"""Scan orchestration: discover files, parse them, run matching checks.

The engine is deliberately dumb — all the security knowledge lives in the
checks. Its job is to be robust: a bad file or a throwing check is isolated and
reported, never fatal. This is what makes the scanner safe to point at a large,
messy repository.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from cloudnova.core.check import CheckRegistry
from cloudnova.core.check import registry as default_registry
from cloudnova.core.findings import Finding
from cloudnova.core.loader import LoadError, discover, load_file


@dataclass
class ScanResult:
    """Everything a scan produced: findings plus operational metadata."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    checks_run: int = 0
    errors: list[str] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key())

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)


class Engine:
    """Runs the registered checks against a target path."""

    def __init__(self, checks: CheckRegistry | None = None) -> None:
        self._registry = checks or default_registry

    def scan_path(self, root: Path) -> ScanResult:
        result = ScanResult()
        for path in discover(root):
            try:
                artifact = load_file(path)
            except LoadError as exc:
                result.errors.append(str(exc))
                continue

            result.files_scanned += 1
            for check in self._registry.for_target(artifact.kind):
                result.checks_run += 1
                try:
                    result.findings.extend(check.run(artifact))
                except Exception as exc:
                    result.errors.append(f"check {check.id} failed on {path}: {exc}")
        return result
