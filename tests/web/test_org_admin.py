"""Organization settings UI: members, invitations, roles.

Controls are hidden by role, but hiding is presentation only - the database
refuses regardless. These tests check both: that the right controls appear,
and that a refusal from Supabase reaches the user instead of a 500.
"""

from __future__ import annotations

import json
import re

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
import httpx

SESSION = {
    "access_token": "user-jwt",
    "refresh_token": "refresh-xyz",
    "expires_in": 3600,
    "user": {"id": "user-1", "email": "omar@example.test"},
}
USER = {"id": "user-1", "email": "omar@example.test"}

MEMBERS = [
    {
        "user_id": "user-1",
        "role": "owner",
        "created_at": "2026-09-01T00:00:00Z",
        "profiles": {"email": "omar@example.test", "full_name": "Omar"},
    },
    {
        "user_id": "user-2",
        "role": "member",
        "created_at": "2026-09-05T00:00:00Z",
        "profiles": {"email": "sam@example.test", "full_name": "Sam"},
    },
]
INVITES = [
    {
        "id": "inv-1",
        "email": "pending@example.test",
        "role": "admin",
        "status": "pending",
        "created_at": "2026-09-20T00:00:00Z",
        "expires_at": "2026-10-04T00:00:00Z",
    }
]


def _supabase(*, role="owner", members=None, invites=None, on_rest=None):
    org = {"id": "org-1", "name": "Acme"}

    def handler(request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/auth/v1/token":
            return httpx.Response(200, json=SESSION)
        if path == "/auth/v1/user":
            return httpx.Response(200, json=USER)
        if path == "/rest/v1/memberships" and method == "GET":
            select = request.url.params.get("select", "")
            if "organizations" in select:
                return httpx.Response(200, json=[{"role": role, "organizations": org}])
            return httpx.Response(200, json=MEMBERS if members is None else members)
        if on_rest is not None:
            custom = on_rest(request)
            if custom is not None:
                return custom
        if path == "/rest/v1/invitations" and method == "GET":
            return httpx.Response(200, json=INVITES if invites is None else invites)
        if path.startswith("/rest/v1/"):
            return httpx.Response(200, json=[])
        return httpx.Response(404, json={"msg": f"unexpected {method} {path}"})

    return handler


def _signed_in(platform_app, **kw):
    app, seen = platform_app(_supabase(**kw))
    app.post(
        "/login",
        data={"email": "omar@example.test", "password": "pw"},
        follow_redirects=False,
    )
    seen.clear()
    return app, seen


# -- the page --------------------------------------------------------------


def test_settings_lists_members_with_names_and_roles(platform_app):
    app, _ = _signed_in(platform_app)
    r = app.get("/org")
    assert r.status_code == 200
    assert "Omar" in r.text and "Sam" in r.text
    assert "sam@example.test" in r.text


def test_settings_lists_pending_invitations(platform_app):
    app, _ = _signed_in(platform_app)
    r = app.get("/org")
    assert "pending@example.test" in r.text
    assert "Revoke" in r.text


def test_owner_sees_invite_and_role_controls(platform_app):
    app, _ = _signed_in(platform_app, role="owner")
    r = app.get("/org")
    assert "Send invitation" in r.text
    assert 'action="/org/member/role"' in r.text or "/org/member/role" in r.text


def test_viewer_is_not_offered_controls_they_cannot_use(platform_app):
    app, _ = _signed_in(platform_app, role="viewer")
    r = app.get("/org")
    assert "Send invitation" not in r.text
    assert "Only owners and admins can invite" in r.text
    assert "Remove" not in r.text


def test_admin_can_invite_but_not_change_roles(platform_app):
    # Role changes are owner-only in the schema, so an admin is not offered them.
    app, _ = _signed_in(platform_app, role="admin")
    r = app.get("/org")
    assert "Send invitation" in r.text
    assert "/org/member/role" not in r.text


def test_you_are_never_offered_controls_against_yourself(platform_app):
    app, _ = _signed_in(platform_app, role="owner")
    r = app.get("/org")
    # Quote-agnostic: the markup uses single quotes for these attributes.
    targets = set(re.findall(r"name=['\"]user_id['\"] value=['\"]([^'\"]+)['\"]", r.text))
    # Sam can be acted on; Omar (the caller) is never a target.
    assert "user-2" in targets
    assert "user-1" not in targets


def test_settings_page_is_gated(platform_app):
    app, _ = platform_app(_supabase())
    assert app.get("/org", follow_redirects=False).status_code == 303


def test_org_routes_absent_in_local_mode(client):
    assert client.get("/org").status_code == 404
    assert client.get("/invites").status_code == 404


# -- inviting --------------------------------------------------------------


def test_invite_posts_the_right_row(platform_app):
    created = {}

    def on_rest(request):
        if request.url.path == "/rest/v1/invitations" and request.method == "POST":
            created["body"] = json.loads(request.content)[0]
            return httpx.Response(201, json=[{**INVITES[0], "email": "new@example.test"}])
        return None

    app, _ = _signed_in(platform_app, on_rest=on_rest)
    r = app.post("/org/invite", data={"email": "new@example.test", "role": "admin"})
    assert r.status_code == 200
    assert created["body"]["org_id"] == "org-1"
    assert created["body"]["email"] == "new@example.test"
    assert created["body"]["role"] == "admin"
    assert created["body"]["invited_by"] == "user-1"
    assert "Invitation sent" in r.text


def test_invite_with_a_bad_address_is_reported_not_sent(platform_app):
    app, seen = _signed_in(platform_app)
    r = app.post("/org/invite", data={"email": "nonsense", "role": "member"})
    assert r.status_code == 200
    assert "email address" in r.text
    assert not [s for s in seen if s.url.path == "/rest/v1/invitations" and s.method == "POST"]


def test_invite_denied_by_rls_shows_the_refusal(platform_app):
    def on_rest(request):
        if request.url.path == "/rest/v1/invitations" and request.method == "POST":
            return httpx.Response(403, json={"message": "row-level security policy"})
        return None

    app, _ = _signed_in(platform_app, role="viewer", on_rest=on_rest)
    r = app.post("/org/invite", data={"email": "new@example.test", "role": "member"})
    assert r.status_code == 200
    assert "row-level security" in r.text


def test_revoke_patches_the_invitation(platform_app):
    patched = {}

    def on_rest(request):
        if request.url.path == "/rest/v1/invitations" and request.method == "PATCH":
            patched["body"] = json.loads(request.content)
            patched["id"] = request.url.params.get("id")
            return httpx.Response(204, content=b"")
        return None

    app, _ = _signed_in(platform_app, on_rest=on_rest)
    r = app.post("/org/invite/revoke", data={"invitation_id": "inv-1"})
    assert patched["body"] == {"status": "revoked"}
    assert patched["id"] == "eq.inv-1"
    assert "Invitation revoked" in r.text


# -- roles and removal -----------------------------------------------------


def test_change_role_patches_the_membership(platform_app):
    patched = {}

    def on_rest(request):
        if request.url.path == "/rest/v1/memberships" and request.method == "PATCH":
            patched["body"] = json.loads(request.content)
            patched["params"] = dict(request.url.params)
            return httpx.Response(204, content=b"")
        return None

    app, _ = _signed_in(platform_app, on_rest=on_rest)
    r = app.post("/org/member/role", data={"user_id": "user-2", "role": "admin"})
    assert patched["body"] == {"role": "admin"}
    assert patched["params"]["org_id"] == "eq.org-1"
    assert patched["params"]["user_id"] == "eq.user-2"
    assert "Role updated" in r.text


def test_you_cannot_change_your_own_role(platform_app):
    # The only thing this enables is demoting yourself out of the last owner
    # seat and locking the org.
    app, seen = _signed_in(platform_app)
    r = app.post("/org/member/role", data={"user_id": "user-1", "role": "viewer"})
    assert "cannot change your own role" in r.text
    assert not [s for s in seen if s.method == "PATCH"]


def test_you_cannot_remove_yourself(platform_app):
    app, seen = _signed_in(platform_app)
    r = app.post("/org/member/remove", data={"user_id": "user-1"})
    assert "cannot remove yourself" in r.text
    assert not [s for s in seen if s.method == "DELETE"]


def test_remove_member_deletes_the_membership(platform_app):
    captured = {}

    def on_rest(request):
        if request.url.path == "/rest/v1/memberships" and request.method == "DELETE":
            captured["params"] = dict(request.url.params)
            return httpx.Response(204, content=b"")
        return None

    app, _ = _signed_in(platform_app, on_rest=on_rest)
    r = app.post("/org/member/remove", data={"user_id": "user-2"})
    assert captured["params"]["user_id"] == "eq.user-2"
    assert captured["params"]["org_id"] == "eq.org-1"
    assert "Member removed" in r.text


def test_role_change_refused_by_rls_is_shown(platform_app):
    def on_rest(request):
        if request.url.path == "/rest/v1/memberships" and request.method == "PATCH":
            return httpx.Response(403, json={"message": "row-level security policy"})
        return None

    app, _ = _signed_in(platform_app, role="admin", on_rest=on_rest)
    r = app.post("/org/member/role", data={"user_id": "user-2", "role": "owner"})
    assert "row-level security" in r.text


# -- creating and joining --------------------------------------------------


def test_creating_an_org_switches_to_it(platform_app):
    def on_rest(request):
        # Creation goes through the RPC now, see migration 0005.
        if request.url.path == "/rest/v1/rpc/create_organization":
            return httpx.Response(200, json={"id": "org-new", "name": "Globex"})
        return None

    app, _ = _signed_in(platform_app, on_rest=on_rest)
    r = app.post("/orgs/create", data={"name": "Globex"}, follow_redirects=False)
    assert r.status_code == 303
    assert "cn_org=org-new" in r.headers["set-cookie"]


def test_creating_an_org_with_a_blank_name_does_nothing(platform_app):
    app, seen = _signed_in(platform_app)
    r = app.post("/orgs/create", data={"name": "   "}, follow_redirects=False)
    assert r.status_code == 303
    assert not [s for s in seen if "create_organization" in s.url.path]


def test_invites_page_lists_what_you_were_sent(platform_app):
    def on_rest(request):
        if request.url.path == "/rest/v1/invitations" and request.method == "GET":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": "inv-9",
                        "email": "omar@example.test",
                        "role": "member",
                        "expires_at": "2026-10-20T00:00:00Z",
                        "organizations": {"id": "org-x", "name": "Initech"},
                    }
                ],
            )
        return None

    app, _ = _signed_in(platform_app, on_rest=on_rest)
    r = app.get("/invites")
    assert "Initech" in r.text
    assert "Accept" in r.text


def test_accepting_goes_through_the_rpc_and_switches_org(platform_app):
    called = {}

    def on_rest(request):
        if request.url.path == "/rest/v1/rpc/accept_invitation":
            called["body"] = json.loads(request.content)
            return httpx.Response(200, json="org-joined")
        return None

    app, _ = _signed_in(platform_app, on_rest=on_rest)
    r = app.post("/invites/accept", data={"invitation_id": "inv-9"}, follow_redirects=False)
    assert called["body"] == {"invitation_id": "inv-9"}
    assert r.status_code == 303
    assert "cn_org=org-joined" in r.headers["set-cookie"]


def test_accepting_someone_elses_invitation_changes_nothing(platform_app):
    def on_rest(request):
        if request.url.path == "/rest/v1/rpc/accept_invitation":
            return httpx.Response(404, json={"message": "Invitation not found."})
        return None

    app, _ = _signed_in(platform_app, on_rest=on_rest)
    r = app.post("/invites/accept", data={"invitation_id": "not-mine"}, follow_redirects=False)
    assert r.status_code == 303
    assert "cn_org" not in r.headers.get("set-cookie", "")
