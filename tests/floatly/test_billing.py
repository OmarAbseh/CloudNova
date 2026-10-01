"""Billing entitlements: which plan an org is on, and what that allows.

Written before the implementation. The decisions being pinned down here are
the ones that are easy to get quietly wrong: what an org with no subscription
row gets, whether a pending invitation consumes a seat, what a lapsed
subscription falls back to, and what happens when the lookup itself fails.
"""

from __future__ import annotations

import pytest

pytest.importorskip("httpx")
import httpx

from cloudnova.platform.billing import (
    FREE_PLAN,
    Plan,
    Usage,
    entitlements,
    get_usage,
    list_plans,
)

PRO = {
    "id": "pro",
    "name": "Pro",
    "price_cents": 4900,
    "currency": "eur",
    "max_seats": 10,
    "max_scans_per_month": 1000,
}
ENTERPRISE = {
    "id": "enterprise",
    "name": "Enterprise",
    "price_cents": 0,
    "currency": "eur",
    "max_seats": None,
    "max_scans_per_month": None,
}


def _json(payload, status=200):
    return httpx.Response(status, json=payload)


def _usage(seats=1, pending=0, scans=0):
    return _json([{"seats": seats, "pending_invites": pending, "scans_this_month": scans}])


def _subscription(plan_id="pro", status="active"):
    plan = {"pro": PRO, "enterprise": ENTERPRISE}[plan_id]
    return _json([{"plan_id": plan_id, "status": status, "plans": plan}])


# -- the catalogue ---------------------------------------------------------


def test_list_plans_reads_the_catalogue(make_client):
    client, rec = make_client([_json([PRO, ENTERPRISE])])
    plans = list_plans(client, "user-jwt")
    assert [p.id for p in plans] == ["pro", "enterprise"]
    assert plans[0].max_seats == 10
    assert plans[1].max_seats is None  # null means unlimited
    assert rec.path() == "/rest/v1/plans"


# -- usage -----------------------------------------------------------------


def test_usage_comes_from_the_rpc(make_client):
    client, rec = make_client([_usage(seats=3, pending=2, scans=17)])
    usage = get_usage(client, "user-jwt", "org-1")
    assert usage == Usage(seats=3, pending_invites=2, scans_this_month=17)
    assert rec.path() == "/rest/v1/rpc/org_usage"
    assert rec.body() == {"target_org": "org-1"}


def test_usage_of_an_org_you_cannot_see_is_zero(make_client):
    # org_usage runs with invoker rights, so RLS gives a non-member zeros
    # rather than another org's counts.
    client, _ = make_client([_json([])])
    assert get_usage(client, "user-jwt", "not-mine") == Usage(0, 0, 0)


# -- which plan applies ----------------------------------------------------


def test_no_subscription_row_means_the_free_plan(make_client):
    # Absence is a valid state; nothing has to backfill a row for billing to
    # work, so an org that never subscribed is simply on free.
    client, _ = make_client([_json([]), _usage()])
    ent = entitlements(client, "user-jwt", "org-1")
    assert ent.plan == FREE_PLAN
    assert ent.status == "none"


def test_an_active_subscription_uses_its_plan(make_client):
    client, _ = make_client([_subscription("pro"), _usage()])
    ent = entitlements(client, "user-jwt", "org-1")
    assert ent.plan.id == "pro"
    assert ent.plan.max_seats == 10


def test_a_canceled_subscription_falls_back_to_free(make_client):
    # Otherwise cancelling would leave the org on its old limits forever.
    client, _ = make_client([_subscription("pro", status="canceled"), _usage()])
    ent = entitlements(client, "user-jwt", "org-1")
    assert ent.plan == FREE_PLAN
    assert ent.status == "canceled"


def test_past_due_keeps_the_plan_as_a_grace_period(make_client):
    # A failed card should not instantly lock a security team out of scanning;
    # Stripe retries for days before giving up.
    client, _ = make_client([_subscription("pro", status="past_due"), _usage()])
    assert entitlements(client, "user-jwt", "org-1").plan.id == "pro"


def test_trialing_gets_the_full_plan(make_client):
    client, _ = make_client([_subscription("pro", status="trialing"), _usage()])
    assert entitlements(client, "user-jwt", "org-1").plan.id == "pro"


# -- seats -----------------------------------------------------------------


def test_a_pending_invitation_holds_a_seat(make_client):
    # Without this, a one-seat org could invite a hundred people and only hit
    # the limit as each one accepted.
    client, _ = make_client([_json([]), _usage(seats=1, pending=0)])
    assert entitlements(client, "user-jwt", "org-1").can_add_seat is False

    client, _ = make_client([_subscription("pro"), _usage(seats=4, pending=6)])
    ent = entitlements(client, "user-jwt", "org-1")
    assert ent.seats_used == 10
    assert ent.can_add_seat is False


def test_seats_remaining_counts_down(make_client):
    client, _ = make_client([_subscription("pro"), _usage(seats=4, pending=1)])
    ent = entitlements(client, "user-jwt", "org-1")
    assert ent.seats_used == 5
    assert ent.seats_remaining == 5
    assert ent.can_add_seat is True


def test_unlimited_seats_never_block(make_client):
    client, _ = make_client([_subscription("enterprise"), _usage(seats=500, pending=20)])
    ent = entitlements(client, "user-jwt", "org-1")
    assert ent.seats_remaining is None
    assert ent.can_add_seat is True


# -- scans -----------------------------------------------------------------


def test_scans_block_at_the_monthly_limit(make_client):
    client, _ = make_client([_json([]), _usage(scans=20)])
    ent = entitlements(client, "user-jwt", "org-1")
    assert ent.plan.max_scans_per_month == 20
    assert ent.can_run_scan is False
    assert ent.scans_remaining == 0


def test_scans_allowed_below_the_limit(make_client):
    client, _ = make_client([_json([]), _usage(scans=19)])
    ent = entitlements(client, "user-jwt", "org-1")
    assert ent.can_run_scan is True
    assert ent.scans_remaining == 1


def test_going_over_the_limit_does_not_report_negative_headroom(make_client):
    # A plan downgrade can leave usage above the new limit.
    client, _ = make_client([_json([]), _usage(seats=9, scans=50)])
    ent = entitlements(client, "user-jwt", "org-1")
    assert ent.scans_remaining == 0
    assert ent.seats_remaining == 0
    assert ent.can_run_scan is False


def test_unlimited_scans_never_block(make_client):
    client, _ = make_client([_subscription("enterprise"), _usage(scans=100000)])
    ent = entitlements(client, "user-jwt", "org-1")
    assert ent.scans_remaining is None
    assert ent.can_run_scan is True


# -- failure ---------------------------------------------------------------


def test_a_billing_outage_does_not_block_scanning(make_client):
    # Deliberate: failing closed would let a billing hiccup stop a security
    # team from scanning. The gate opens and says why, rather than silently
    # pretending everything is fine.
    client, _ = make_client([_json({"message": "database is on fire"}, status=500)])
    ent = entitlements(client, "user-jwt", "org-1")
    assert ent.can_run_scan is True
    assert ent.can_add_seat is True
    assert ent.degraded is True
    assert "on fire" in ent.error


def test_a_healthy_lookup_is_not_marked_degraded(make_client):
    client, _ = make_client([_subscription("pro"), _usage()])
    ent = entitlements(client, "user-jwt", "org-1")
    assert ent.degraded is False
    assert ent.error == ""


def test_free_plan_constant_matches_the_seeded_catalogue(make_client):
    # The fallback must agree with migration 0004, or an org with no row would
    # silently get different limits from one that explicitly chose free.
    assert (
        Plan(
            id="free",
            name="Free",
            price_cents=0,
            currency="eur",
            max_seats=1,
            max_scans_per_month=20,
        )
        == FREE_PLAN
    )
