"""Password recovery: request a link, then set a new password.

The security property under test is that none of these responses reveal
whether an email address has an account.
"""

from __future__ import annotations

import pytest

pytest.importorskip("httpx")
import httpx

from cloudnova.platform.client import AuthError, SupabaseError


def _ok(payload=None, status=200):
    return lambda request: httpx.Response(status, json=payload if payload is not None else {})


def test_request_reset_posts_to_recover(make_client, config):
    client, rec = make_client(_ok({}))
    client.request_password_reset("omar@example.test", redirect_to="https://app/reset")
    assert rec.path() == "/auth/v1/recover"
    assert rec.body()["email"] == "omar@example.test"
    # Where the link lands has to be told to Supabase explicitly.
    assert rec.last.url.params["redirect_to"] == "https://app/reset"
    # No session exists yet, so the anon key is its own bearer.
    assert rec.bearer() == config.anon_key


def test_request_reset_without_a_redirect_sends_none(make_client):
    client, rec = make_client(_ok({}))
    client.request_password_reset("omar@example.test")
    assert "redirect_to" not in rec.last.url.params


def test_an_unknown_address_is_not_distinguishable(make_client):
    # Supabase answers 200 either way; this asserts we do not turn a
    # non-answer into an error the caller could use to enumerate accounts.
    client, _ = make_client(_ok({}))
    client.request_password_reset("nobody@example.test")


def test_rate_limiting_surfaces_as_an_error(make_client):
    client, _ = make_client(_ok({"msg": "email rate limit exceeded"}, status=429))
    with pytest.raises(SupabaseError, match="rate limit"):
        client.request_password_reset("omar@example.test")


def test_verify_recovery_exchanges_a_token_for_a_session(make_client):
    client, rec = make_client(
        _ok(
            {
                "access_token": "recovery-jwt",
                "refresh_token": "r",
                "expires_in": 3600,
                "user": {"id": "user-1", "email": "omar@example.test"},
            }
        )
    )
    session = client.verify_recovery("hash-abc")
    assert session.access_token == "recovery-jwt"
    assert session.user_id == "user-1"
    assert rec.path() == "/auth/v1/verify"
    assert rec.body() == {"type": "recovery", "token_hash": "hash-abc"}


def test_an_expired_link_is_rejected_clearly(make_client):
    client, _ = make_client(_ok({"msg": "Token has expired or is invalid"}, status=401))
    with pytest.raises(AuthError, match="expired"):
        client.verify_recovery("stale")


def test_verify_without_a_session_in_the_reply_is_an_error(make_client):
    client, _ = make_client(_ok({"user": {"id": "x"}}))
    with pytest.raises(AuthError):
        client.verify_recovery("odd")


def test_set_password_uses_the_recovery_session(make_client):
    client, rec = make_client(_ok({"id": "user-1"}))
    client.set_password("recovery-jwt", "new-strong-password")
    assert rec.last.method == "PUT"
    assert rec.path() == "/auth/v1/user"
    # Signed with the recovery session, not the anon key, or anyone could
    # change anyone's password.
    assert rec.bearer() == "recovery-jwt"
    assert rec.body() == {"password": "new-strong-password"}


def test_a_rejected_password_says_why(make_client):
    client, _ = make_client(_ok({"msg": "Password should be at least 6 characters"}, status=422))
    with pytest.raises(AuthError, match="at least 6 characters"):
        client.set_password("recovery-jwt", "x")
