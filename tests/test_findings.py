"""The data model is the contract; lock its guarantees down."""

import pytest
from pydantic import ValidationError

from cloudnova.core.findings import Confidence, Finding, Location, Severity


def _finding(**overrides):
    base = {
        "check_id": "X",
        "title": "t",
        "severity": Severity.HIGH,
        "location": Location(path="a"),
        "description": "d",
        "remediation": "r",
    }
    base.update(overrides)
    return Finding(**base)


def test_severity_rank_is_ordered():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.INFO.rank


def test_finding_is_frozen():
    f = _finding()
    with pytest.raises(ValidationError):
        f.title = "mutated"


def test_sort_key_orders_critical_first():
    crit = _finding(severity=Severity.CRITICAL, check_id="A")
    low = _finding(severity=Severity.LOW, check_id="B")
    assert sorted([low, crit], key=lambda f: f.sort_key())[0] is crit


def test_defaults():
    f = _finding()
    assert f.confidence is Confidence.HIGH
    assert f.references == []
    assert f.detected_at is not None
