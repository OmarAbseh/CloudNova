"""Org lifecycle: members, invitations, roles.

The database is the enforcement point - proven against the live project in
the migrations. What these pin down is the layer above: the right request,
under the caller's own token, and a denial surfaced rather than swallowed.
"""

from __future__ import annotations

import pytest

pytest.importorskip("httpx")
import httpx

from cloudnova.platform.client import SupabaseError
from cloudnova.platform.tenancy import (
    accept_invitation,
    change_role,
    create_org,
    invite_member,
    list_invitations,
    list_members,
    list_my_invitations,
    remove_member,
    revoke_invitation,
)


def _json(payload, status=200):
    return httpx.Response(status, json=payload)


DENIED = {"message": "new row violates row-level security policy"}


# -- members ---------------------------------------------------------------


def test_list_members_joins_profiles_for_names(make_client):
    client, rec = make_client(
        [
            _json(
                [
                    {
                        "user_id": "user-1",
                        "role": "owner",
                        "created_at": "2026-09-01T00:00:00Z",
                        "profiles": {"email": "omar@example.test", "full_name": "Omar"},
                    },
                    {
                        "user_id": "user-2",
                        "role": "viewer",
                        "created_at": "2026-09-02T00:00:00Z",
                        "profiles": None,
                    },
                ]
            )
        ]
    )
    members = list_members(client, "user-jwt", "org-1")
    assert [(m.user_id, m.role, m.email, m.full_name) for m in members] == [
        ("user-1", "owner", "omar@example.test", "Omar"),
        # A profile the caller cannot read degrades to blanks, not a crash.
        ("user-2", "viewer", "", ""),
    ]
    assert rec.last.url.params["org_id"] == "eq.org-1"
    assert rec.bearer() == "user-jwt"


def test_change_role_patches_one_membership(make_client):
    client, rec = make_client([httpx.Response(204, content=b"")])
    change_role(client, "user-jwt", "org-1", "user-2", "admin")
    assert rec.last.method == "PATCH"
    assert rec.body() == {"role": "admin"}
    # Both filters present, or the patch could hit another org's row.
    assert rec.last.url.params["org_id"] == "eq.org-1"
    assert rec.last.url.params["user_id"] == "eq.user-2"


def test_change_role_rejects_an_unknown_role(make_client):
    client, rec = make_client([])
    with pytest.raises(ValueError, match="unknown role"):
        change_role(client, "user-jwt", "org-1", "user-2", "superadmin")
    assert rec.requests == []  # refused before any request went out


def test_change_role_surfaces_an_rls_denial(make_client):
    # Only an owner may change a role; the database says so, not this code.
    client, _ = make_client([_json(DENIED, status=403)])
    with pytest.raises(SupabaseError, match="row-level security"):
        change_role(client, "user-jwt", "org-1", "user-2", "owner")


def test_remove_member_deletes_with_both_filters(make_client):
    client, rec = make_client([httpx.Response(204, content=b"")])
    remove_member(client, "user-jwt", "org-1", "user-2")
    assert rec.last.method == "DELETE"
    assert rec.last.url.params["org_id"] == "eq.org-1"
    assert rec.last.url.params["user_id"] == "eq.user-2"


def test_a_filterless_write_is_refused_before_it_is_sent(make_client):
    # A PATCH or DELETE with no filter would hit every row RLS lets the caller
    # touch, which for an owner is their whole org.
    client, rec = make_client([])
    with pytest.raises(ValueError, match="refusing to patch"):
        client.update("memberships", "user-jwt", {"role": "owner"}, params={})
    with pytest.raises(ValueError, match="refusing to clear"):
        client.delete("memberships", "user-jwt", params={})
    assert rec.requests == []


# -- invitations -----------------------------------------------------------


def test_invite_member_posts_the_invitation(make_client):
    client, rec = make_client(
        [
            _json(
                [
                    {
                        "id": "inv-1",
                        "email": "new@example.test",
                        "role": "member",
                        "status": "pending",
                        "created_at": "2026-09-30T00:00:00Z",
                        "expires_at": "2026-10-14T00:00:00Z",
                    }
                ]
            )
        ]
    )
    inv = invite_member(
        client,
        "user-jwt",
        org_id="org-1",
        email="  new@example.test  ",
        role="member",
        invited_by="user-1",
    )
    assert inv.id == "inv-1"
    assert inv.status == "pending"
    body = rec.body()[0]
    assert body["email"] == "new@example.test"  # trimmed
    assert body["org_id"] == "org-1"
    assert body["invited_by"] == "user-1"


def test_invite_rejects_a_bad_address_without_a_request(make_client):
    client, rec = make_client([])
    with pytest.raises(ValueError, match="email address"):
        invite_member(
            client,
            "user-jwt",
            org_id="org-1",
            email="not-an-email",
            role="member",
            invited_by="user-1",
        )
    assert rec.requests == []


def test_invite_rejects_an_unknown_role(make_client):
    client, _ = make_client([])
    with pytest.raises(ValueError, match="unknown role"):
        invite_member(
            client,
            "user-jwt",
            org_id="org-1",
            email="a@b.test",
            role="root",
            invited_by="user-1",
        )


def test_inviting_into_someone_elses_org_is_denied(make_client):
    client, _ = make_client([_json(DENIED, status=403)])
    with pytest.raises(SupabaseError, match="row-level security"):
        invite_member(
            client,
            "user-jwt",
            org_id="not-mine",
            email="a@b.test",
            role="member",
            invited_by="user-1",
        )


def test_duplicate_pending_invite_surfaces_the_conflict(make_client):
    client, _ = make_client(
        [_json({"message": "duplicate key value violates unique constraint"}, status=409)]
    )
    with pytest.raises(SupabaseError, match="duplicate key"):
        invite_member(
            client,
            "user-jwt",
            org_id="org-1",
            email="a@b.test",
            role="member",
            invited_by="user-1",
        )


def test_list_invitations_defaults_to_pending_only(make_client):
    client, rec = make_client([_json([])])
    list_invitations(client, "user-jwt", "org-1")
    assert rec.last.url.params["status"] == "eq.pending"
    assert rec.last.url.params["org_id"] == "eq.org-1"


def test_list_invitations_can_include_history(make_client):
    client, rec = make_client([_json([])])
    list_invitations(client, "user-jwt", "org-1", pending_only=False)
    assert "status" not in rec.last.url.params


def test_list_my_invitations_sends_no_email_filter(make_client):
    # The policy matches against the caller's own verified JWT, so asking for
    # all pending invitations returns exactly theirs. Filtering by an email
    # from the client would be theatre.
    client, rec = make_client([_json([])])
    list_my_invitations(client, "user-jwt")
    assert "email" not in rec.last.url.params
    assert rec.last.url.params["status"] == "eq.pending"
    assert rec.bearer() == "user-jwt"


def test_revoke_marks_rather_than_deletes(make_client):
    # Keeping the row means the org's history still shows it was sent.
    client, rec = make_client([httpx.Response(204, content=b"")])
    revoke_invitation(client, "user-jwt", "inv-1")
    assert rec.last.method == "PATCH"
    assert rec.body() == {"status": "revoked"}
    assert rec.last.url.params["id"] == "eq.inv-1"


# -- accepting -------------------------------------------------------------


def test_accept_calls_the_rpc_and_returns_the_org(make_client):
    client, rec = make_client([_json("org-1")])
    assert accept_invitation(client, "user-jwt", "inv-1") == "org-1"
    assert rec.path() == "/rest/v1/rpc/accept_invitation"
    assert rec.body() == {"invitation_id": "inv-1"}
    assert rec.bearer() == "user-jwt"


def test_accepting_an_invitation_for_someone_else_is_rejected(make_client):
    # The function raises P0002 with a deliberately vague message so it cannot
    # be used to probe which addresses were invited where.
    client, _ = make_client([_json({"message": "Invitation not found."}, status=404)])
    with pytest.raises(SupabaseError, match="Invitation not found"):
        accept_invitation(client, "user-jwt", "someone-elses-invite")


def test_accept_returning_nothing_is_an_error_not_a_silent_pass(make_client):
    client, _ = make_client([_json(None)])
    with pytest.raises(SupabaseError, match="Invitation not found"):
        accept_invitation(client, "user-jwt", "inv-1")


def test_expired_invitation_message_is_surfaced(make_client):
    client, _ = make_client([_json({"message": "This invitation has expired."}, status=404)])
    with pytest.raises(SupabaseError, match="expired"):
        accept_invitation(client, "user-jwt", "inv-1")


# -- creating orgs ---------------------------------------------------------


def test_create_org_goes_through_the_rpc(make_client):
    # Regression, see migration 0005. A plain insert that asks for the row back
    # is an INSERT ... RETURNING, and RETURNING is checked against the SELECT
    # policy, which is false until the founding membership exists. In
    # production the row was created and then rejected on the way out with a
    # 403. The old fake returned a row regardless, so nothing caught it.
    client, rec = make_client([_json({"id": "org-9", "name": "Globex"})])
    org = create_org(client, "user-jwt", "user-1", "Globex")
    assert (org.id, org.name, org.role) == ("org-9", "Globex", "owner")
    assert rec.path() == "/rest/v1/rpc/create_organization"
    # No created_by is sent: the function takes it from auth.uid(), so the
    # creator cannot be forged by the caller.
    assert rec.body() == {"org_name": "Globex"}


def test_create_org_failure_is_surfaced(make_client):
    client, _ = make_client([_json({"message": "Not signed in."}, status=401)])
    with pytest.raises(SupabaseError):
        create_org(client, "user-jwt", "user-1", "Globex")


# -- audit trail -----------------------------------------------------------


def test_record_event_appends_with_the_caller_as_actor(make_client):
    import httpx

    from cloudnova.platform.tenancy import record_event

    client, rec = make_client([httpx.Response(201, content=b"")])
    record_event(
        client,
        "user-jwt",
        org_id="org-1",
        actor="user-1",
        action="scan.completed",
        detail={"findings": 3},
    )
    assert rec.path() == "/rest/v1/audit_log"
    body = rec.body()[0]
    assert body["org_id"] == "org-1"
    # The policy requires actor = auth.uid(), so an event cannot be attributed
    # to somebody else even if this code tried.
    assert body["actor"] == "user-1"
    assert body["action"] == "scan.completed"
    assert body["detail"] == {"findings": 3}


def test_record_event_never_breaks_the_action_it_describes(make_client):
    # Losing an audit line is bad; failing a member's scan because the audit
    # write failed is worse. The caller is not given the chance to crash.
    import httpx

    from cloudnova.platform.tenancy import record_event

    client, _ = make_client([httpx.Response(500, json={"message": "boom"})])
    record_event(client, "user-jwt", org_id="org-1", actor="user-1", action="x", detail={})


def test_list_audit_reads_newest_first_for_one_org(make_client):
    from cloudnova.platform.tenancy import list_audit

    client, rec = make_client(
        [
            _json(
                [
                    {
                        "action": "scan.completed",
                        "created_at": "2026-10-03T00:00:00Z",
                        "detail": {},
                        "profiles": {"email": "a@b.test"},
                    }
                ]
            )
        ]
    )
    rows = list_audit(client, "user-jwt", "org-1")
    assert len(rows) == 1
    assert rows[0].action == "scan.completed"
    assert rows[0].actor_email == "a@b.test"
    assert rec.last.url.params["org_id"] == "eq.org-1"
    assert rec.last.url.params["order"] == "created_at.desc"


def test_list_audit_tolerates_an_unreadable_actor(make_client):
    from cloudnova.platform.tenancy import list_audit

    client, _ = make_client(
        [_json([{"action": "x", "created_at": "", "detail": None, "profiles": None}])]
    )
    rows = list_audit(client, "user-jwt", "org-1")
    assert rows[0].actor_email == ""
