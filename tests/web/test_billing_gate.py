"""Plan limits as the dashboard applies them.

Written before the wiring. The question each test answers is what a user
actually experiences at a limit — and, just as importantly, what they
experience when billing itself is having a bad day.
"""

from __future__ import annotations

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
PRO = {
    "id": "pro",
    "name": "Pro",
    "price_cents": 4900,
    "currency": "eur",
    "max_seats": 10,
    "max_scans_per_month": 1000,
}


def _supabase(*, seats=1, pending=0, scans=0, plan=None, status="active", on_rest=None):
    org = {"id": "org-1", "name": "Acme"}

    def handler(request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/auth/v1/token":
            return httpx.Response(200, json=SESSION)
        if path == "/auth/v1/user":
            return httpx.Response(200, json=USER)
        if on_rest is not None:
            custom = on_rest(request)
            if custom is not None:
                return custom
        if path == "/rest/v1/memberships" and method == "GET":
            if "organizations" in request.url.params.get("select", ""):
                return httpx.Response(200, json=[{"role": "owner", "organizations": org}])
            return httpx.Response(200, json=[])
        if path == "/rest/v1/rpc/org_usage":
            return httpx.Response(
                200,
                json=[{"seats": seats, "pending_invites": pending, "scans_this_month": scans}],
            )
        if path == "/rest/v1/subscriptions":
            if plan is None:
                return httpx.Response(200, json=[])
            return httpx.Response(
                200, json=[{"plan_id": plan["id"], "status": status, "plans": plan}]
            )
        if path == "/rest/v1/scans" and method == "POST":
            return httpx.Response(201, json=[{"id": "scan-1"}])
        if path == "/rest/v1/targets":
            return httpx.Response(200, json=[{"id": "target-1"}])
        if path.startswith("/rest/v1/"):
            return httpx.Response(200, json=[])
        return httpx.Response(404, json={"msg": f"unexpected {method} {path}"})

    return handler


def _signed_in(platform_app, **kw):
    app, seen = platform_app(_supabase(**kw))
    app.post("/login", data={"email": "omar@example.test", "password": "pw"})
    seen.clear()
    return app, seen


def _tf(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" { acl = "public-read" }\n', encoding="utf-8"
    )
    return str(tmp_path)


def _scan_posts(seen):
    return [r for r in seen if r.url.path == "/rest/v1/scans" and r.method == "POST"]


# -- scan limits -----------------------------------------------------------


def test_scan_runs_when_under_the_limit(platform_app, tmp_path):
    app, seen = _signed_in(platform_app, scans=5)
    r = app.post("/scan", data={"path": _tf(tmp_path)})
    assert r.status_code == 200
    assert "public acl" in r.text.lower()
    assert _scan_posts(seen)


def test_scan_is_refused_at_the_monthly_limit(platform_app, tmp_path):
    # free plan: 20 scans. Refuse before running, not after — there is no
    # point burning the work only to throw the result away.
    app, seen = _signed_in(platform_app, scans=20)
    r = app.post("/scan", data={"path": _tf(tmp_path)})
    assert r.status_code == 200
    assert "monthly scan limit" in r.text.lower()
    assert not _scan_posts(seen)


def test_the_limit_message_says_what_the_limit_is(platform_app, tmp_path):
    app, _ = _signed_in(platform_app, scans=20)
    r = app.post("/scan", data={"path": _tf(tmp_path)})
    assert "20" in r.text
    assert "Free" in r.text


def test_a_paid_plan_raises_the_ceiling(platform_app, tmp_path):
    app, seen = _signed_in(platform_app, scans=25, plan=PRO)
    r = app.post("/scan", data={"path": _tf(tmp_path)})
    assert "limit" not in r.text.lower() or "public acl" in r.text.lower()
    assert _scan_posts(seen)


def test_billing_outage_does_not_block_a_scan(platform_app, tmp_path):
    # Failing closed would let a billing hiccup stop a security team working.
    def on_rest(request):
        if request.url.path in ("/rest/v1/subscriptions", "/rest/v1/rpc/org_usage"):
            return httpx.Response(500, json={"message": "billing is down"})
        return None

    app, seen = _signed_in(platform_app, on_rest=on_rest)
    r = app.post("/scan", data={"path": _tf(tmp_path)})
    assert r.status_code == 200
    assert "public acl" in r.text.lower()
    assert _scan_posts(seen)


def test_local_mode_is_not_metered(client, tmp_path):
    # No platform configured means no orgs, so there is nothing to meter.
    # Assert on the message rather than the word "limit": pytest names tmp_path
    # after the test, and the scanned path is echoed back into the page.
    r = client.post("/scan", data={"path": _tf(tmp_path)})
    assert r.status_code == 200
    assert "monthly scan limit" not in r.text.lower()
    assert "public acl" in r.text.lower()


# -- seat limits -----------------------------------------------------------


def test_invite_is_refused_when_seats_are_full(platform_app):
    # free plan: 1 seat, already used by the owner.
    app, seen = _signed_in(platform_app, seats=1)
    r = app.post("/org/invite", data={"email": "new@example.test", "role": "member"})
    assert r.status_code == 200
    assert "seat" in r.text.lower()
    assert not [s for s in seen if s.url.path == "/rest/v1/invitations" and s.method == "POST"]


def test_invite_allowed_with_a_seat_free(platform_app):
    created = {}

    def on_rest(request):
        if request.url.path == "/rest/v1/invitations" and request.method == "POST":
            created["hit"] = True
            return httpx.Response(201, json=[{"id": "inv-1", "email": "new@example.test"}])
        return None

    app, _ = _signed_in(platform_app, seats=3, plan=PRO, on_rest=on_rest)
    r = app.post("/org/invite", data={"email": "new@example.test", "role": "member"})
    assert created.get("hit")
    assert "Invitation sent" in r.text


def test_pending_invitations_consume_seats_at_the_gate(platform_app):
    # 9 members + 1 pending = 10 of 10 on Pro, so the next invite is refused
    # even though only nine people have actually joined.
    app, seen = _signed_in(platform_app, seats=9, pending=1, plan=PRO)
    r = app.post("/org/invite", data={"email": "new@example.test", "role": "member"})
    assert "seat" in r.text.lower()
    assert not [s for s in seen if s.url.path == "/rest/v1/invitations" and s.method == "POST"]


# -- showing the plan ------------------------------------------------------


def test_org_page_shows_the_plan_and_usage(platform_app):
    app, _ = _signed_in(platform_app, seats=3, scans=7, plan=PRO)
    r = app.get("/org")
    assert "Pro" in r.text
    assert "3" in r.text and "7" in r.text


def test_org_page_shows_the_free_plan_when_there_is_no_subscription(platform_app):
    app, _ = _signed_in(platform_app, seats=1, scans=2)
    r = app.get("/org")
    assert "Free" in r.text


def test_org_page_survives_a_billing_outage(platform_app):
    def on_rest(request):
        if request.url.path in ("/rest/v1/subscriptions", "/rest/v1/rpc/org_usage"):
            return httpx.Response(500, json={"message": "billing is down"})
        return None

    app, _ = _signed_in(platform_app, on_rest=on_rest)
    r = app.get("/org")
    assert r.status_code == 200
    assert "Members" in r.text  # the rest of the page still renders
