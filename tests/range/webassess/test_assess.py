"""Authorization gating: out-of-scope targets are refused and never touch network."""

import pytest

from cloudnova.range.scope import Authorization, Scope
from cloudnova.range.webassess import assess
from cloudnova.range.webassess.model import HttpSnapshot
from cloudnova.range.webassess.probe import NotAuthorizedError, _require_authorized


def _scope(*in_scope: str) -> Scope:
    auth = Authorization(
        program="test", authorized_by="tester", acknowledged=True, reference="TEST-1"
    )
    return Scope(authorization=auth, in_scope=list(in_scope), out_of_scope=[])


def test_out_of_scope_is_denied_without_network(monkeypatch):
    called = False

    def _boom(*a, **k):
        nonlocal called
        called = True
        raise AssertionError("network must not be touched for out-of-scope targets")

    monkeypatch.setattr("cloudnova.range.webassess.runner.fetch", _boom)
    result = assess("https://evil.com", _scope("example.com"))
    assert result.authorized is False
    assert called is False


def test_require_authorized_raises_for_out_of_scope():
    with pytest.raises(NotAuthorizedError):
        _require_authorized("https://evil.com", _scope("example.com"))


def test_in_scope_runs_checks_on_stubbed_snapshot(monkeypatch):
    snap = HttpSnapshot(
        url="http://example.com", status=200, headers={}, tls=False, final_url="http://example.com"
    )
    monkeypatch.setattr("cloudnova.range.webassess.runner.fetch", lambda url, scope: snap)
    monkeypatch.setattr(
        "cloudnova.range.webassess.runner.find_exposed_paths", lambda url, scope: [".env"]
    )
    result = assess("http://example.com", _scope("example.com"))
    assert result.authorized is True
    ids = {f.id for f in result.findings}
    assert "WEB_NO_TLS" in ids  # plaintext transport
    assert "WEB_EXPOSED_SENSITIVE_PATH" in ids  # from stubbed exposed path
    # findings are sorted worst-first
    ranks = [f.severity.rank for f in result.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_wildcard_domain_in_scope(monkeypatch):
    snap = HttpSnapshot(url="https://api.example.com", status=200, headers={}, tls=True)
    monkeypatch.setattr("cloudnova.range.webassess.runner.fetch", lambda url, scope: snap)
    result = assess("https://api.example.com", _scope("*.example.com"), check_paths=False)
    assert result.authorized is True
