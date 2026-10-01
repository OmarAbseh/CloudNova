"""Scheduled scanning support: scan history + drift detection.

CloudNova does not run its own scheduler daemon - that's what cron, systemd timers,
and CI already do well. Instead it makes scheduled scanning *useful*: it records a
timestamped snapshot of each scan, compares a new scan to the previous one, and
reports drift (newly introduced vs fixed findings). Wire `cloudnova monitor` into
cron/GitHub Actions and it becomes continuous monitoring with alerting via exit code.

Storage is isolated here (the only module besides the loader that touches disk for
this feature); everything else is a pure function of report dicts.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cloudnova.diff import ScanDiff, diff_reports


def _data_dir(data_dir: str | None) -> Path:
    if data_dir:
        return Path(data_dir)
    override = os.environ.get("CLOUDNOVA_DATA_DIR")
    return Path(override) if override else Path.home() / ".cloudnova" / "history"


def _target_key(path: str) -> str:
    resolved = str(Path(path).resolve())
    return hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:16]


def _target_dir(path: str, data_dir: str | None) -> Path:
    return _data_dir(data_dir) / _target_key(path)


def list_snapshots(path: str, *, data_dir: str | None = None) -> list[Path]:
    """All snapshot files for a target, oldest first."""
    d = _target_dir(path, data_dir)
    if not d.exists():
        return []
    return sorted(d.glob("*.json"))


def load_latest(path: str, *, data_dir: str | None = None) -> dict[str, Any] | None:
    snaps = list_snapshots(path, data_dir=data_dir)
    if not snaps:
        return None
    try:
        return json.loads(snaps[-1].read_text(encoding="utf-8"))  # type: ignore[no-any-return]
    except (OSError, json.JSONDecodeError):
        return None


def diff_against_latest(
    path: str, report: dict[str, Any], *, data_dir: str | None = None
) -> ScanDiff | None:
    """Diff a fresh report against the most recent snapshot (None if first run)."""
    previous = load_latest(path, data_dir=data_dir)
    if previous is None:
        return None
    return diff_reports(previous, report)


def record_scan(path: str, report: dict[str, Any], *, data_dir: str | None = None) -> Path:
    """Persist a timestamped snapshot of a scan report."""
    d = _target_dir(path, data_dir)
    d.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    out = d / f"{stamp}.json"
    out.write_text(json.dumps(report, default=str), encoding="utf-8")
    return out


def trend(path: str, *, data_dir: str | None = None) -> list[dict[str, Any]]:
    """A time series of (timestamp, score, findings) across snapshots."""
    points: list[dict[str, Any]] = []
    for snap in list_snapshots(path, data_dir=data_dir):
        try:
            report = json.loads(snap.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        summary = report.get("summary", {})
        points.append(
            {
                "timestamp": snap.stem,
                "score": summary.get("posture_score", 0),
                "grade": summary.get("grade", "?"),
                "findings": summary.get("findings", len(report.get("findings", []))),
            }
        )
    return points
