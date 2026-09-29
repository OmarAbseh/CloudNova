"""Compare two scans: what's newly introduced, what's been fixed.

Point-in-time scanning answers "what's wrong now". Teams also need "what changed"
— did this PR *introduce* a finding, or fix one? This diffs a previously saved
JSON report against a fresh scan, matching findings by the same stable fingerprint
the baseline uses (check_id + path + resource + evidence), so reformatting doesn't
create false churn.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any


def fingerprint(finding: dict[str, Any]) -> str:
    """Stable id for a finding dict — matches the baseline's fingerprint fields."""
    loc = finding.get("location") or {}
    parts = "|".join(
        [
            str(finding.get("check_id", "")),
            str(loc.get("path", "")),
            str(loc.get("resource") or ""),
            str(finding.get("evidence") or ""),
        ]
    )
    return hashlib.sha256(parts.encode("utf-8")).hexdigest()[:16]


@dataclass
class ScanDiff:
    """The delta between an old scan and a new one."""

    introduced: list[dict[str, Any]] = field(default_factory=list)
    fixed: list[dict[str, Any]] = field(default_factory=list)
    unchanged: int = 0
    old_score: int = 0
    new_score: int = 0

    @property
    def score_delta(self) -> int:
        """Positive means posture got worse (higher score = worse)."""
        return self.new_score - self.old_score


def diff_findings(
    old: list[dict[str, Any]],
    new: list[dict[str, Any]],
    *,
    old_score: int = 0,
    new_score: int = 0,
) -> ScanDiff:
    """Compute introduced / fixed / unchanged between two finding lists."""
    old_by_fp = {fingerprint(f): f for f in old}
    new_by_fp = {fingerprint(f): f for f in new}

    introduced = [f for fp, f in new_by_fp.items() if fp not in old_by_fp]
    fixed = [f for fp, f in old_by_fp.items() if fp not in new_by_fp]
    unchanged = len(set(old_by_fp) & set(new_by_fp))

    _sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    introduced.sort(key=lambda f: _sev.get(str(f.get("severity")), 9))
    fixed.sort(key=lambda f: _sev.get(str(f.get("severity")), 9))

    return ScanDiff(
        introduced=introduced,
        fixed=fixed,
        unchanged=unchanged,
        old_score=old_score,
        new_score=new_score,
    )


def diff_reports(old_report: dict[str, Any], new_report: dict[str, Any]) -> ScanDiff:
    """Diff two full JSON reports (as produced by the scan --format json output)."""
    return diff_findings(
        old_report.get("findings", []),
        new_report.get("findings", []),
        old_score=old_report.get("summary", {}).get("posture_score", 0),
        new_score=new_report.get("summary", {}).get("posture_score", 0),
    )
