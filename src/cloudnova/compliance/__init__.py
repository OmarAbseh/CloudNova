"""Compliance mapping: turn scan findings into framework control status.

Maps CloudNova findings onto ISO 27001, NIST CSF, and PCI DSS controls and reports
per-control PASS / FAIL / NOT_ASSESSED with an honest coverage-based score.
"""

from cloudnova.compliance.engine import (
    ComplianceReport,
    ControlResult,
    ControlState,
    assess,
    assess_all,
)
from cloudnova.compliance.frameworks import Category, Framework, categorize

__all__ = [
    "Category",
    "ComplianceReport",
    "ControlResult",
    "ControlState",
    "Framework",
    "assess",
    "assess_all",
    "categorize",
]
