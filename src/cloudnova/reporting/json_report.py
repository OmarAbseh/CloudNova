"""JSON report formatter.

Machine-readable output for CI gates, diffing two scans, or feeding an AI
agent. Uses Pydantic's own serialisation so the schema always matches the
model — no hand-maintained dict that can drift out of sync.
"""

from __future__ import annotations

import json

from cloudnova.core.engine import ScanResult


def render_json(result: ScanResult, *, indent: int = 2) -> str:
    payload = {
        "summary": {
            "files_scanned": result.files_scanned,
            "checks_run": result.checks_run,
            "findings": len(result.findings),
            "errors": len(result.errors),
        },
        "findings": [f.model_dump(mode="json") for f in result.sorted_findings()],
        "errors": result.errors,
    }
    return json.dumps(payload, indent=indent, default=str)
