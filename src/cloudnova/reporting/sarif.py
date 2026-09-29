"""SARIF 2.1.0 report formatter.

SARIF is the interchange format GitHub code-scanning ingests, so emitting it
lets CloudNova findings appear inline on pull requests and in the Security tab.
We build the ``rules`` array from the checks that actually fired and attach the
``security-severity`` property GitHub uses to rank alerts.
"""

from __future__ import annotations

import json
from typing import Any

from cloudnova import __version__
from cloudnova.core.engine import ScanResult
from cloudnova.core.findings import Finding, Severity

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF has three levels; map our five-band severity onto them.
_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub ranks alerts by a numeric 0-10 "security-severity" string.
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def _rule(finding: Finding) -> dict[str, Any]:
    props: dict[str, Any] = {"security-severity": _SECURITY_SEVERITY[finding.severity]}
    tags = ["security"]
    tags += [f"cis:{c}" for c in finding.cis_controls]
    tags += [f"mitre:{m}" for m in finding.mitre_attack]
    props["tags"] = tags
    rule: dict[str, Any] = {
        "id": finding.check_id,
        "name": finding.check_id,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "help": {"text": finding.remediation},
        "defaultConfiguration": {"level": _LEVEL[finding.severity]},
        "properties": props,
    }
    if finding.references:
        rule["helpUri"] = finding.references[0]
    return rule


def _result(finding: Finding) -> dict[str, Any]:
    region: dict[str, Any] = {}
    if finding.location.line is not None:
        region["startLine"] = finding.location.line
    physical: dict[str, Any] = {"artifactLocation": {"uri": finding.location.path}}
    if region:
        physical["region"] = region
    message = finding.description
    if finding.location.resource:
        message = f"[{finding.location.resource}] {message}"
    return {
        "ruleId": finding.check_id,
        "level": _LEVEL[finding.severity],
        "message": {"text": message},
        "locations": [{"physicalLocation": physical}],
    }


def render_sarif(result: ScanResult, *, indent: int = 2) -> str:
    findings = result.sorted_findings()
    # One rule object per unique check that fired, in first-seen order.
    rules: dict[str, dict[str, Any]] = {}
    for f in findings:
        rules.setdefault(f.check_id, _rule(f))

    document = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CloudNova",
                        "version": __version__,
                        "informationUri": "https://github.com/OmarAbseh/CloudNova",
                        "rules": list(rules.values()),
                    }
                },
                "results": [_result(f) for f in findings],
            }
        ],
    }
    return json.dumps(document, indent=indent, default=str)
