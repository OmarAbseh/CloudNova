"""Baseline support: accept known findings so scans surface only what's new.

A real codebase adopting a scanner starts with a backlog of findings it can't
fix all at once. A baseline records a stable fingerprint for each accepted
finding; later scans subtract those, so CI only fails on *newly introduced*
issues. Fingerprints deliberately exclude volatile fields (timestamps, free
text) so they stay stable across runs and tool versions.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from cloudnova.core.engine import ScanResult
from cloudnova.core.findings import Finding


def fingerprint(finding: Finding) -> str:
    """A stable id for a finding, independent of when or how it was reported.

    Built from the rule, the file, the specific resource, and the evidence — the
    things that identify *this* issue — hashed so the baseline file is compact
    and doesn't leak long strings.
    """
    parts = "|".join(
        [
            finding.check_id,
            finding.location.path,
            finding.location.resource or "",
            finding.evidence or "",
        ]
    )
    return hashlib.sha256(parts.encode("utf-8")).hexdigest()[:16]


@dataclass
class Baseline:
    """A set of accepted finding fingerprints, persisted as JSON."""

    fingerprints: set[str] = field(default_factory=set)

    @classmethod
    def from_result(cls, result: ScanResult) -> Baseline:
        return cls({fingerprint(f) for f in result.findings})

    @classmethod
    def load(cls, path: Path) -> Baseline:
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(set(data.get("fingerprints", [])))

    def save(self, path: Path) -> None:
        payload = {
            "version": 1,
            "fingerprints": sorted(self.fingerprints),
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def contains(self, finding: Finding) -> bool:
        return fingerprint(finding) in self.fingerprints

    def filter(self, result: ScanResult) -> ScanResult:
        """Return a copy of ``result`` with baselined findings removed."""
        kept = [f for f in result.findings if not self.contains(f)]
        return ScanResult(
            findings=kept,
            files_scanned=result.files_scanned,
            checks_run=result.checks_run,
            errors=list(result.errors),
        )
