"""Dashboard authentication: gating, sign-in/up/out, sessions, cookies.

Covers both modes — local single-user (no platform configured) and
multi-tenant (Supabase wired up) — because the difference between them is a
security boundary, not a feature flag.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
import httpx

from cloudnova.web.auth import ACCESS_COOKIE, REFRESH_COOKIE

SESSION = {
    "access_token": "user-jwt",
    "refresh_token": "refresh-xyz",
    "expires_in": 3600,
    "user": {"id": "user-1", "email": "omar@example.test"},
}
USER = {"id": "user-1", "email": "omar@example.test"}


def _route(request: httpx.Request) -> httpx.Response:
    """A Supabase that accepts 'user-jwt' and rejects everything else."""
    path = request.url.path
    if path == "/auth/v1/token":
        return httpx.Response(200, json=SESSION)
    if path == "/auth/v1/signup":
        return httpx.Response(200, json=SESSION)
    if path == "/auth/v1/user":
        token = request.headers["Authorization"].removeprefix("Bearer ")
        if token == "user-jwt":
            return httpx.Response(200, json=USER)
        return httpx.Response(401, json={"msg": "invalid claim"})
    if path == "/auth/v1/logout":
        return httpx.Response(204)
    if path.startswith("/rest/v1/"):
        return httpx.Response(200, json=[])
    return httpx.Response(404, json={"msg": f"unexpected {path}"})


# -- local single-user mode -------------------------------------------------


def test_local_mode_needs_no_account(client):
    # Unconfigured, the tool stays what it always was: no login wall.
    assert client.get("/").status_code == 200
    assert client.get("/scan").status_code == 200


def test_local_mode_has_no_login_routes(client):
    # Rendering a sign-in form that cannot authenticate anyone would be a lie.
    assert client.get("/login").status_code == 404
    assert client.post("/logout").status_code == 404


def test_local_mode_shows_no_account_chrome(client):
    assert "Sign out" not in client.get("/").text


# -- gating -----------------------------------------------------------------


def test_anonymous_is_redirected_to_login(platform_app):
    app, _ = platform_app(_route)
    r = app.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_every_app_route_is_gated(platform_app):
    app, _ = platform_app(_route)
    for path in ("/", "/scan", "/mentor"):
        assert app.get(path, follow_redirects=False).status_code == 303, path


def test_scan_post_is_gated_too(platform_app):
    # Gating only GETs would leave the scanner itself reachable.
    app, _ = platform_app(_route)
    r = app.post("/scan", data={"path": "/etc"}, follow_redirects=False)
    assert r.status_code == 303


def test_health_stays_open_for_probes(platform_app):
    app, _ = platform_app(_route)
    assert app.get("/health").status_code == 200


def test_login_page_is_reachable_anonymously(platform_app):
    app, _ = platform_app(_route)
    r = app.get("/login")
    assert r.status_code == 200
    assert "Sign in" in r.text


def test_redirects_carry_security_headers(platform_app):
    # An unauthenticated redirect is still a framable response.
    app, _ = platform_app(_route)
    r = app.get("/", follow_redirects=False)
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in r.headers


# -- sign in ----------------------------------------------------------------


def test_login_sets_httponly_session_cookies(platform_app):
    app, _ = platform_app(_route)
    r = app.post(
        "/login",
        data={"email": "omar@example.test", "password": "pw"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/"
    jar = {c.name: c for c in r.cookies.jar}
    assert ACCESS_COOKIE in jar
    assert REFRESH_COOKIE in jar
    raw = r.headers["set-cookie"]
    assert "HttpOnly" in raw
    assert "SameSite=lax" in raw.lower() or "samesite=lax" in raw.lower()


def test_login_is_not_secure_flagged_on_localhost(platform_app):
    # A Secure cookie over plain-HTTP localhost is never stored, which would
    # silently break local login.
    app, _ = platform_app(_route)
    r = app.post("/login", data={"email": "a@b.test", "password": "pw"}, follow_redirects=False)
    assert "secure" not in r.headers["set-cookie"].lower()


def test_session_cookie_grants_access(platform_app):
    app, _ = platform_app(_route)
    app.post("/login", data={"email": "omar@example.test", "password": "pw"})
    r = app.get("/")
    assert r.status_code == 200
    assert "omar@example.test" in r.text  # account chrome appears
    assert "Sign out" in r.text


def test_bad_credentials_rerender_with_401(platform_app):
    def handler(request):
        if request.url.path == "/auth/v1/token":
            return httpx.Response(400, json={"error_description": "Invalid login credentials"})
        return _route(request)

    app, _ = platform_app(handler)
    r = app.post("/login", data={"email": "a@b.test", "password": "nope"})
    assert r.status_code == 401
    assert "Invalid login credentials" in r.text
    assert not [c for c in r.cookies.jar if c.name == ACCESS_COOKIE]


def test_supabase_outage_on_login_is_a_502_not_a_crash(platform_app):
    def handler(request):
        raise httpx.ConnectError("down")

    app, _ = platform_app(handler)
    r = app.post("/login", data={"email": "a@b.test", "password": "pw"})
    assert r.status_code == 502
    assert "Could not reach Supabase" in r.text


def test_signed_in_user_visiting_login_is_sent_home(platform_app):
    app, _ = platform_app(_route)
    app.post("/login", data={"email": "omar@example.test", "password": "pw"})
    r = app.get("/login", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/"


# -- sign up ----------------------------------------------------------------


def test_signup_with_autoconfirm_signs_you_in(platform_app):
    app, _ = platform_app(_route)
    r = app.post(
        "/signup", data={"email": "new@example.test", "password": "pw"}, follow_redirects=False
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/"
    assert [c for c in r.cookies.jar if c.name == ACCESS_COOKIE]


def test_signup_needing_confirmation_says_so_instead_of_pretending(platform_app):
    # Supabase returns the user with no session when confirmation is required.
    def handler(request):
        if request.url.path == "/auth/v1/signup":
            return httpx.Response(200, json={"id": "user-9", "email": "new@example.test"})
        return _route(request)

    app, _ = platform_app(handler)
    r = app.post("/signup", data={"email": "new@example.test", "password": "pw"})
    assert r.status_code == 200
    assert "Confirm your email" in r.text
    assert not [c for c in r.cookies.jar if c.name == ACCESS_COOKIE]


def test_signup_rejection_is_shown(platform_app):
    def handler(request):
        if request.url.path == "/auth/v1/signup":
            return httpx.Response(422, json={"msg": "Password should be at least 6 characters"})
        return _route(request)

    app, _ = platform_app(handler)
    r = app.post("/signup", data={"email": "new@example.test", "password": "x"})
    assert r.status_code == 400
    assert "at least 6 characters" in r.text


# -- sessions ---------------------------------------------------------------


def test_expired_token_is_refreshed_and_the_new_pair_stored(platform_app):
    state = {"refreshed": False}

    def handler(request):
        path = request.url.path
        if path == "/auth/v1/user":
            token = request.headers["Authorization"].removeprefix("Bearer ")
            if token == "fresh-jwt":
                return httpx.Response(200, json=USER)
            return httpx.Response(401, json={"msg": "expired"})
        if path == "/auth/v1/token" and request.url.params.get("grant_type") == "refresh_token":
            state["refreshed"] = True
            return httpx.Response(200, json={**SESSION, "access_token": "fresh-jwt"})
        return _route(request)

    app, _ = platform_app(handler)
    app.cookies.set(ACCESS_COOKIE, "stale-jwt")
    app.cookies.set(REFRESH_COOKIE, "refresh-xyz")

    r = app.get("/")
    assert r.status_code == 200
    assert state["refreshed"]
    # The rotated token must be written back or the browser replays the dead
    # one. Read it off the response rather than the jar, which still holds the
    # stale cookie this test seeded by hand.
    assert f"{ACCESS_COOKIE}=fresh-jwt" in r.headers["set-cookie"]


def test_forged_cookie_cannot_render_a_signed_in_page(platform_app):
    # The cookie is never trusted on its own; Supabase is asked every request.
    app, _ = platform_app(_route)
    app.cookies.set(ACCESS_COOKIE, "forged-not-a-real-jwt")
    r = app.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_dead_session_cookies_are_cleared(platform_app):
    def handler(request):
        if request.url.path == "/auth/v1/user":
            return httpx.Response(401, json={"msg": "bad"})
        if request.url.path == "/auth/v1/token":
            return httpx.Response(400, json={"msg": "refresh revoked"})
        return _route(request)

    app, _ = platform_app(handler)
    app.cookies.set(ACCESS_COOKIE, "dead")
    app.cookies.set(REFRESH_COOKIE, "also-dead")
    r = app.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert 'cn_access=""' in r.headers["set-cookie"] or "cn_access=;" in r.headers["set-cookie"]


def test_supabase_outage_does_not_destroy_a_live_session(platform_app):
    # An outage must not log everyone out; the cookie is left alone.
    def handler(request):
        raise httpx.ConnectError("down")

    app, _ = platform_app(handler)
    app.cookies.set(ACCESS_COOKIE, "user-jwt")
    r = app.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert "set-cookie" not in r.headers


# -- sign out ---------------------------------------------------------------


def test_logout_clears_cookies_and_revokes_server_side(platform_app):
    app, seen = platform_app(_route)
    app.post("/login", data={"email": "omar@example.test", "password": "pw"})
    r = app.post("/logout", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"
    assert any(req.url.path == "/auth/v1/logout" for req in seen)
    assert not app.cookies.get(ACCESS_COOKIE)


def test_logout_still_clears_cookies_when_revocation_fails(platform_app):
    # Otherwise a Supabase hiccup leaves the user stuck signed in.
    def handler(request):
        if request.url.path == "/auth/v1/logout":
            return httpx.Response(500, json={"msg": "nope"})
        return _route(request)

    app, _ = platform_app(handler)
    app.post("/login", data={"email": "omar@example.test", "password": "pw"})
    r = app.post("/logout", follow_redirects=False)
    assert r.status_code == 303
    assert not app.cookies.get(ACCESS_COOKIE)
