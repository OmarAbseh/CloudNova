"""Scope engine: deny-by-default, exclusions win, attestation required."""

from pathlib import Path

import pytest

from cloudnova.range import ScopeError, load_scope
from cloudnova.range.scope import Authorization, Scope

_VALID_AUTH = Authorization(
    program="Test Program", authorized_by="policy", acknowledged=True, reference="url"
)


def _scope(in_scope, out_of_scope=None, auth=_VALID_AUTH):
    return Scope(authorization=auth, in_scope=in_scope, out_of_scope=out_of_scope or [])


def test_in_scope_domain_allowed():
    assert _scope(["api.example.com"]).authorize("api.example.com").allowed


def test_unknown_target_denied_by_default():
    d = _scope(["api.example.com"]).authorize("evil.com")
    assert not d.allowed
    assert "deny by default" in d.reason


def test_wildcard_domain_matches_subdomains_and_base():
    s = _scope(["*.example.com"])
    assert s.authorize("a.example.com").allowed
    assert s.authorize("example.com").allowed
    # Must NOT match a look-alike domain.
    assert not s.authorize("evil-example.com").allowed


def test_exclusion_beats_inclusion():
    s = _scope(["*.example.com"], ["admin.example.com"])
    assert s.authorize("api.example.com").allowed
    assert not s.authorize("admin.example.com").allowed


def test_cidr_matching():
    s = _scope(["10.0.0.0/8"])
    assert s.authorize("10.1.2.3").allowed
    assert not s.authorize("192.168.0.1").allowed


def test_exact_ip():
    s = _scope(["203.0.113.5"])
    assert s.authorize("203.0.113.5").allowed
    assert not s.authorize("203.0.113.6").allowed


def test_missing_attestation_fails_closed():
    bad = Authorization(program="", authorized_by="", acknowledged=False)
    s = Scope(authorization=bad, in_scope=["*.example.com"])
    d = s.authorize("api.example.com")
    assert not d.allowed
    assert "fail closed" in d.reason


def test_unacknowledged_attestation_fails_closed():
    s = Scope(
        authorization=Authorization("P", "policy", acknowledged=False),
        in_scope=["api.example.com"],
    )
    assert not s.authorize("api.example.com").allowed


def test_cloud_account_id_exact_match():
    s = _scope(["123456789012"])
    assert s.authorize("123456789012").allowed
    assert not s.authorize("999999999999").allowed


def test_empty_target_denied():
    assert not _scope(["*.example.com"]).authorize("  ").allowed


def test_load_scope_roundtrip(tmp_path: Path):
    f = tmp_path / "scope.yaml"
    f.write_text(
        "authorization:\n  program: P\n  authorized_by: policy\n  acknowledged: true\n"
        "in_scope:\n  - '*.example.com'\nout_of_scope:\n  - admin.example.com\n",
        encoding="utf-8",
    )
    scope = load_scope(f)
    assert scope.authorization.is_valid()
    assert scope.authorize("x.example.com").allowed
    assert not scope.authorize("admin.example.com").allowed


def test_load_scope_requires_authorization(tmp_path: Path):
    f = tmp_path / "scope.yaml"
    f.write_text("in_scope:\n  - '*.example.com'\n", encoding="utf-8")
    with pytest.raises(ScopeError, match="authorization"):
        load_scope(f)


def test_load_scope_requires_in_scope(tmp_path: Path):
    f = tmp_path / "scope.yaml"
    f.write_text(
        "authorization:\n  program: P\n  authorized_by: policy\n  acknowledged: true\n",
        encoding="utf-8",
    )
    with pytest.raises(ScopeError, match="in_scope"):
        load_scope(f)
