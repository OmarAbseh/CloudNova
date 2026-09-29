"""Active detection: pure signature logic + param probing over stubbed responses."""

from cloudnova.range.scope import Authorization, Scope
from cloudnova.range.webassess import active


def _scope(*hosts: str) -> Scope:
    auth = Authorization(program="t", authorized_by="me", acknowledged=True)
    return Scope(authorization=auth, in_scope=list(hosts), out_of_scope=[])


def test_marker_reflection_detection():
    assert active.body_reflects_marker(f"<p>{active.XSS_MARKER}</p>") is True
    assert active.body_reflects_marker("clean output") is False


def test_sql_error_signature():
    assert active.sql_error_signature("You have an error in your SQL syntax; near") is not None
    assert active.sql_error_signature("all good") is None


def test_passwd_signature():
    assert active.body_reads_passwd("root:x:0:0:root:/root:/bin/bash") is True
    assert active.body_reads_passwd("nothing here") is False


def test_detect_reflected_xss_flags_params(monkeypatch):
    monkeypatch.setattr(active, "get_body", lambda url, scope: (200, active.XSS_MARKER))
    hits = active.detect_reflected_xss("https://ex.com/s?q=1&r=2", _scope("ex.com"))
    assert set(hits) == {"q", "r"}


def test_detect_sql_injection_flags_param(monkeypatch):
    monkeypatch.setattr(
        active, "get_body", lambda url, scope: (500, "Warning: mysql_fetch_array()")
    )
    hits = active.detect_sql_injection("https://ex.com/s?id=1", _scope("ex.com"))
    assert hits == ["id"]


def test_no_params_no_hits(monkeypatch):
    monkeypatch.setattr(active, "get_body", lambda url, scope: (200, active.XSS_MARKER))
    assert active.detect_reflected_xss("https://ex.com/", _scope("ex.com")) == []
