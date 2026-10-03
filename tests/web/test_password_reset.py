"""Password recovery through the dashboard.

Without this, a user who forgets their password is locked out permanently.
The property that matters most is that no response here tells an attacker
whether an address has an account.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
import httpx

SESSION = {
    "access_token": "recovery-jwt",
    "refresh_token": "r",
    "expires_in": 3600,
    "user": {"id": "user-1", "email": "omar@example.test"},
}
USER = {"id": "user-1", "email": "omar@example.test"}


def _supabase(*, on_auth=None):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if on_auth is not None:
            custom = on_auth(request)
            if custom is not None:
                return custom
        if path == "/auth/v1/recover":
            return httpx.Response(200, json={})
        if path == "/auth/v1/verify":
            return httpx.Response(200, json=SESSION)
        if path == "/auth/v1/user":
            return httpx.Response(200, json=USER)
        if path == "/auth/v1/token":
            return httpx.Response(200, json=SESSION)
        if path == "/rest/v1/memberships":
            return httpx.Response(
                200, json=[{"role": "owner", "organizations": {"id": "org-1", "name": "Acme"}}]
            )
        if path.startswith("/rest/v1/"):
            return httpx.Response(200, json=[])
        return httpx.Response(404, json={"msg": f"unexpected {path}"})

    return handler


# -- reachability ----------------------------------------------------------


def test_forgot_is_reachable_without_signing_in(platform_app):
    # Asking a locked-out user to sign in to reach the page that fixes that
    # would be a closed loop.
    app, _ = platform_app(_supabase())
    r = app.get("/forgot")
    assert r.status_code == 200
    assert "Send reset link" in r.text


def test_login_offers_the_way_out(platform_app):
    app, _ = platform_app(_supabase())
    assert "/forgot" in app.get("/login").text


def test_reset_is_reachable_without_signing_in(platform_app):
    app, _ = platform_app(_supabase())
    assert app.get("/reset", params={"token_hash": "abc"}).status_code == 200


def test_reset_routes_absent_in_local_mode(client):
    assert client.get("/forgot").status_code == 404
    assert client.get("/reset").status_code == 404


# -- requesting a link ----------------------------------------------------


def test_requesting_a_link_calls_recover_with_a_redirect(platform_app):
    app, seen = platform_app(_supabase())
    r = app.post("/forgot", data={"email": "omar@example.test"})
    assert r.status_code == 200
    calls = [s for s in seen if s.url.path == "/auth/v1/recover"]
    assert calls
    # Supabase has to be told where the link should land.
    assert "/reset" in calls[0].url.params["redirect_to"]


def test_the_answer_is_identical_for_an_unknown_address(platform_app):
    # Anything else is an account enumeration oracle.
    app, _ = platform_app(_supabase())
    known = app.post("/forgot", data={"email": "omar@example.test"})
    unknown = app.post("/forgot", data={"email": "nobody@example.test"})
    assert known.status_code == unknown.status_code == 200
    assert "On its way" in known.text and "On its way" in unknown.text
    for page in (known.text, unknown.text):
        assert "no account" not in page.lower()
        assert "not found" not in page.lower()


def test_rate_limiting_is_reported_rather_than_looking_like_success(platform_app):
    def on_auth(request):
        if request.url.path == "/auth/v1/recover":
            return httpx.Response(429, json={"msg": "email rate limit exceeded"})
        return None

    app, _ = platform_app(_supabase(on_auth=on_auth))
    r = app.post("/forgot", data={"email": "omar@example.test"})
    assert r.status_code == 502
    assert "rate limit" in r.text


# -- setting a new password -----------------------------------------------


def test_a_link_without_a_token_says_so(platform_app):
    app, _ = platform_app(_supabase())
    r = app.get("/reset")
    assert "That link is incomplete" in r.text
    assert "/forgot" in r.text


def test_the_form_carries_the_token_forward(platform_app):
    app, _ = platform_app(_supabase())
    r = app.get("/reset", params={"token_hash": "hash-abc"})
    assert 'name="token_hash"' in r.text
    assert 'value="hash-abc"' in r.text


def test_saving_a_password_verifies_then_sets_it(platform_app):
    app, seen = platform_app(_supabase())
    r = app.post(
        "/reset",
        data={"token_hash": "hash-abc", "password": "new-strong-pass"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    paths = [s.url.path for s in seen]
    assert "/auth/v1/verify" in paths
    puts = [s for s in seen if s.url.path == "/auth/v1/user" and s.method == "PUT"]
    assert puts
    # Signed with the recovery session, not the anon key.
    assert puts[0].headers["Authorization"] == "Bearer recovery-jwt"


def test_a_successful_reset_signs_you_in(platform_app):
    # They have just proved they control the address; a login form would be
    # busywork.
    app, _ = platform_app(_supabase())
    r = app.post(
        "/reset",
        data={"token_hash": "hash-abc", "password": "new-strong-pass"},
        follow_redirects=False,
    )
    assert r.headers["location"] == "/"
    assert "cn_access=recovery-jwt" in r.headers["set-cookie"]


def test_an_expired_link_is_refused_and_no_password_is_set(platform_app):
    def on_auth(request):
        if request.url.path == "/auth/v1/verify":
            return httpx.Response(401, json={"msg": "Token has expired or is invalid"})
        return None

    app, seen = platform_app(_supabase(on_auth=on_auth))
    r = app.post("/reset", data={"token_hash": "stale", "password": "new-strong-pass"})
    assert r.status_code == 400
    assert "expired" in r.text
    assert not [s for s in seen if s.method == "PUT"]


def test_a_weak_password_is_reported_with_the_token_kept(platform_app):
    def on_auth(request):
        if request.url.path == "/auth/v1/user" and request.method == "PUT":
            return httpx.Response(422, json={"msg": "Password should be at least 6 characters"})
        return None

    app, _ = platform_app(_supabase(on_auth=on_auth))
    r = app.post("/reset", data={"token_hash": "hash-abc", "password": "x"})
    assert r.status_code == 400
    assert "at least 6 characters" in r.text
    # The user should not have to go back to their email to try again.
    assert 'value="hash-abc"' in r.text
