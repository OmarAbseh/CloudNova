"""Checklist runner + report: auto/active/manual states, scope gating, DarkShield report."""

import pytest

from cloudnova.range.checklist import render_report, run_checklist, summary_counts
from cloudnova.range.checklist.model import State
from cloudnova.range.scope import (
    SELF_AUTH_PROGRAM,
    Authorization,
    Scope,
    self_authorized_scope,
)
from cloudnova.range.webassess.model import HttpSnapshot


def _scope(*hosts: str) -> Scope:
    auth = Authorization(program="t", authorized_by="me", acknowledged=True)
    return Scope(authorization=auth, in_scope=list(hosts), out_of_scope=[])


@pytest.fixture
def stub_probes(monkeypatch):
    snap = HttpSnapshot(
        url="https://example.com",
        status=200,
        headers={},  # no security headers => several FAILs
        cookies=[],  # SESS-002 => N/A
        final_url="https://example.com",
        tls=True,
    )
    monkeypatch.setattr("cloudnova.range.checklist.runner.fetch", lambda url, scope: snap)
    monkeypatch.setattr("cloudnova.range.checklist.runner.find_exposed_paths", lambda *a, **k: [])
    monkeypatch.setattr("cloudnova.range.checklist.runner.risky_methods", lambda *a, **k: set())
    return snap


def _state(run, item_id):
    return next(ri.state for ri in run.items if ri.item.id == item_id)


def test_scope_denied_never_runs(monkeypatch):
    called = False

    def _boom(*a, **k):
        nonlocal called
        called = True
        raise AssertionError("must not fetch out-of-scope")

    monkeypatch.setattr("cloudnova.range.checklist.runner.fetch", _boom)
    run = run_checklist("https://evil.com", _scope("example.com"))
    assert run.authorized is False and called is False


def test_auto_items_resolved(stub_probes):
    run = run_checklist("https://example.com", _scope("example.com"))
    assert run.authorized is True
    assert _state(run, "CONF-007") is State.FAIL  # HSTS missing on TLS
    assert _state(run, "CLNT-009") is State.FAIL  # no X-Frame-Options
    assert _state(run, "ATHN-001") is State.PASS  # served over TLS
    assert _state(run, "CONF-008") is State.PASS  # no wildcard CORS
    assert _state(run, "SESS-002") is State.NA  # no cookies
    assert _state(run, "INFO-002") is State.INFO  # banner (informational)


def test_manual_and_active_are_todo_without_active(stub_probes):
    run = run_checklist("https://example.com", _scope("example.com"))
    assert _state(run, "PRE-001") is State.TODO  # manual
    assert _state(run, "INPV-001") is State.TODO  # active, opt-in required


def test_active_mode_detects(stub_probes, monkeypatch):
    monkeypatch.setattr(
        "cloudnova.range.checklist.runner.detect_reflected_xss", lambda *a, **k: ["q"]
    )
    monkeypatch.setattr("cloudnova.range.checklist.runner.detect_sql_injection", lambda *a, **k: [])
    monkeypatch.setattr(
        "cloudnova.range.checklist.runner.detect_path_traversal", lambda *a, **k: []
    )
    run = run_checklist("https://example.com?q=1", _scope("example.com"), active=True)
    assert _state(run, "INPV-001") is State.FAIL
    assert _state(run, "INPV-005") is State.PASS


def test_report_has_darkshield_sections(stub_probes):
    run = run_checklist("https://example.com", _scope("example.com"))
    report = render_report(run, client="Acme")
    assert "Vulnerability Report" in report
    assert "Vulnerability Summary" in report
    assert "Methodology Checklist" in report
    assert "DS-001" in report  # at least one finding tabled
    counts = summary_counts(run)
    assert counts["Moderate"] >= 1  # HSTS/clickjacking are Moderate


def test_self_authorized_scope():
    scope = self_authorized_scope("myserver.local", "Omar")
    assert scope.authorize("myserver.local").allowed is True
    assert scope.authorization.program == SELF_AUTH_PROGRAM
    assert scope.authorization.authorized_by == "Omar"
