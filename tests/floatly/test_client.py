"""The Supabase client: request signing, session parsing, error surfacing.

The security-critical assertions here are about *which* token signs a request.
"""

from __future__ import annotations

import time

import pytest

pytest.importorskip("httpx")
import httpx

from cloudnova.platform.client import AuthError, SupabaseError


def _ok(payload, status=200):
    return lambda request: httpx.Response(status, json=payload)


# -- auth ------------------------------------------------------------------


def test_sign_in_returns_session_and_sends_anon_key(make_client, session_payload, config):
    client, rec = make_client(_ok(session_payload()))
    session = client.sign_in("omar@example.test", "pw")

    assert session.access_token == "user-jwt"
    assert session.user_id == "user-1"
    assert session.email == "omar@example.test"
    assert not session.expired
    # Before sign-in there is no user token, so the anon key is its own bearer.
    assert rec.last.headers["apikey"] == config.anon_key
    assert rec.bearer() == config.anon_key
    assert rec.last.url.params["grant_type"] == "password"


def test_sign_in_rejects_bad_credentials_with_safe_message(make_client):
    client, _ = make_client(_ok({"error_description": "Invalid login credentials"}, status=400))
    with pytest.raises(AuthError, match="Invalid login credentials"):
        client.sign_in("omar@example.test", "wrong")


def test_sign_in_without_token_in_body_is_an_auth_error(make_client):
    # A 200 that carries no access_token must not be read as success.
    client, _ = make_client(_ok({"user": {"id": "x"}}))
    with pytest.raises(AuthError):
        client.sign_in("omar@example.test", "pw")


def test_sign_up_returning_no_session_means_confirmation_required(make_client):
    # Supabase returns the user but no session when email confirmation is on.
    client, _ = make_client(_ok({"id": "user-9", "email": "new@example.test"}))
    assert client.sign_up("new@example.test", "pw") is None


def test_sign_up_with_autoconfirm_returns_a_session(make_client, session_payload):
    client, _ = make_client(_ok(session_payload()))
    assert client.sign_up("new@example.test", "pw") is not None


def test_expires_at_is_absolute_when_only_expires_in_given(make_client, session_payload):
    client, _ = make_client(_ok(session_payload(expires_in=120)))
    session = client.sign_in("a@b.test", "pw")
    assert time.time() + 100 < session.expires_at <= time.time() + 120


def test_session_counts_as_expired_within_the_skew_window(make_client, session_payload):
    # A token expiring in 10s is treated as already gone, so a request in
    # flight across the boundary does not fail.
    client, _ = make_client(_ok(session_payload(expires_in=10)))
    assert client.sign_in("a@b.test", "pw").expired


def test_refresh_uses_the_refresh_grant(make_client, session_payload):
    client, rec = make_client(_ok(session_payload(access_token="fresh-jwt")))
    session = client.refresh("refresh-xyz")
    assert session.access_token == "fresh-jwt"
    assert rec.last.url.params["grant_type"] == "refresh_token"
    assert rec.body()["refresh_token"] == "refresh-xyz"


def test_get_user_sends_the_user_token_not_the_anon_key(make_client):
    client, rec = make_client(_ok({"id": "user-1", "email": "omar@example.test"}))
    assert client.get_user("user-jwt")["id"] == "user-1"
    assert rec.bearer() == "user-jwt"


def test_get_user_rejects_a_bogus_token(make_client):
    client, _ = make_client(_ok({"msg": "invalid claim"}, status=401))
    with pytest.raises(AuthError):
        client.get_user("forged")


def test_get_user_without_an_id_is_rejected(make_client):
    client, _ = make_client(_ok({}))
    with pytest.raises(AuthError):
        client.get_user("odd-but-200")


def test_sign_out_swallows_failures(make_client):
    # Logout failing server-side must not block clearing the cookie, or the
    # user gets stuck signed in.
    client, _ = make_client(_ok({"msg": "nope"}, status=500))
    client.sign_out("user-jwt")  # no raise


# -- data ------------------------------------------------------------------


def test_select_signs_with_the_user_token(make_client, config):
    client, rec = make_client(_ok([{"id": "org-1"}]))
    rows = client.select("organizations", "user-jwt", params={"select": "id"})
    assert rows == [{"id": "org-1"}]
    assert rec.bearer() == "user-jwt"
    assert rec.last.headers["apikey"] == config.anon_key
    assert rec.path() == "/rest/v1/organizations"


def test_insert_signs_with_user_token_and_returns_the_row(make_client):
    client, rec = make_client(_ok([{"id": "t-1"}]))
    rows = client.insert("targets", "user-jwt", [{"name": "x"}])
    assert rows == [{"id": "t-1"}]
    assert rec.bearer() == "user-jwt"
    assert rec.last.headers["Prefer"] == "return=representation"
    assert rec.body() == [{"name": "x"}]


def test_insert_can_skip_the_returned_representation(make_client):
    client, rec = make_client(lambda r: httpx.Response(201, content=b""))
    assert client.insert("findings", "user-jwt", [{"a": 1}], returning=False) == []
    assert rec.last.headers["Prefer"] == "return=minimal"


def test_insert_of_nothing_makes_no_request(make_client):
    client, rec = make_client(_ok([]))
    assert client.insert("findings", "user-jwt", []) == []
    assert rec.requests == []


def test_rls_denial_surfaces_as_an_error(make_client):
    # What a cross-tenant write looks like coming back from PostgREST.
    client, _ = make_client(
        _ok({"message": "new row violates row-level security policy"}, status=403)
    )
    with pytest.raises(SupabaseError, match="row-level security"):
        client.insert("targets", "user-jwt", [{"org_id": "someone-elses"}])


def test_select_tolerates_a_non_list_body(make_client):
    client, _ = make_client(_ok({"unexpected": True}))
    assert client.select("scans", "user-jwt") == []


def test_network_failure_becomes_a_supabase_error(make_client):
    def _boom(request):
        raise httpx.ConnectError("no route to host")

    client, _ = make_client(_boom)
    with pytest.raises(SupabaseError, match="Could not reach Supabase"):
        client.select("scans", "user-jwt")


def test_non_json_error_body_falls_back_to_a_generic_message(make_client):
    client, _ = make_client(lambda r: httpx.Response(500, content=b"<html>oops</html>"))
    with pytest.raises(SupabaseError, match="Could not read scans"):
        client.select("scans", "user-jwt")
