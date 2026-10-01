"""Plans, subscriptions and entitlements.

Billing hangs off the organization: a seat is a membership and a scan belongs
to an org, so the org is the only thing a limit sensibly applies to.

Nothing here can *change* what an org is entitled to. ``subscriptions`` has no
write policy and no write grant, so these functions can only read — a plan
changes when Stripe's webhook says it did, never because a user asked.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cloudnova.platform.client import SupabaseClient, SupabaseError

# Statuses that still entitle an org to its paid plan. `past_due` is included
# on purpose: Stripe retries a failed card for days, and locking a security
# team out of scanning on the first failure is the wrong trade. `canceled` and
# `incomplete` fall back to free.
_ENTITLING_STATUSES = frozenset({"active", "trialing", "past_due"})

# Used when an org has no subscription row at all. Absence is a valid state —
# nothing has to backfill a row for billing to work — so this must agree with
# the `free` row seeded in migration 0004 or the two paths would diverge.
_PLAN_COLUMNS = "id,name,price_cents,currency,max_seats,max_scans_per_month"


@dataclass(frozen=True)
class Plan:
    id: str
    name: str
    price_cents: int
    currency: str
    # None means unlimited. Zero would mean "none allowed", which is different.
    max_seats: int | None
    max_scans_per_month: int | None


FREE_PLAN = Plan(
    id="free",
    name="Free",
    price_cents=0,
    currency="eur",
    max_seats=1,
    max_scans_per_month=20,
)


@dataclass(frozen=True)
class Usage:
    seats: int
    pending_invites: int
    scans_this_month: int


def _remaining(limit: int | None, used: int) -> int | None:
    """Headroom, floored at zero. None stays None — unlimited has no floor.

    A downgrade can leave usage above the new limit, and reporting negative
    headroom reads as a bug everywhere it is displayed.
    """
    if limit is None:
        return None
    return max(0, limit - used)


@dataclass(frozen=True)
class Entitlements:
    """What an org may currently do, and why."""

    plan: Plan
    usage: Usage
    status: str
    # True when the lookup itself failed. The gate opens in that case rather
    # than blocking a security scan over a billing outage, but it says so.
    degraded: bool = False
    error: str = ""

    @property
    def seats_used(self) -> int:
        # A pending invitation holds a seat. Otherwise a one-seat org could
        # invite a hundred people and only hit the limit as each accepted.
        return self.usage.seats + self.usage.pending_invites

    @property
    def seats_remaining(self) -> int | None:
        return _remaining(self.plan.max_seats, self.seats_used)

    @property
    def scans_remaining(self) -> int | None:
        return _remaining(self.plan.max_scans_per_month, self.usage.scans_this_month)

    @property
    def can_add_seat(self) -> bool:
        if self.degraded:
            return True
        return self.seats_remaining is None or self.seats_remaining > 0

    @property
    def can_run_scan(self) -> bool:
        if self.degraded:
            return True
        return self.scans_remaining is None or self.scans_remaining > 0


def _plan(row: dict[str, Any]) -> Plan:
    return Plan(
        id=str(row.get("id") or "free"),
        name=str(row.get("name") or "Free"),
        price_cents=int(row.get("price_cents") or 0),
        currency=str(row.get("currency") or "eur"),
        max_seats=row.get("max_seats"),
        max_scans_per_month=row.get("max_scans_per_month"),
    )


def list_plans(client: SupabaseClient, token: str) -> list[Plan]:
    """The catalogue, cheapest first. A price list, not tenant data."""
    rows = client.select(
        "plans",
        token,
        params={"select": _PLAN_COLUMNS, "order": "sort_order.asc"},
    )
    return [_plan(row) for row in rows]


def get_usage(client: SupabaseClient, token: str, org_id: str) -> Usage:
    """Seats and scans for an org.

    Backed by a SECURITY INVOKER function, so RLS applies and a caller who is
    not a member gets zeros rather than someone else's counts.
    """
    result = client.rpc("org_usage", token, {"target_org": org_id})
    rows = result if isinstance(result, list) else []
    if not rows or not isinstance(rows[0], dict):
        return Usage(0, 0, 0)
    row = rows[0]
    return Usage(
        seats=int(row.get("seats") or 0),
        pending_invites=int(row.get("pending_invites") or 0),
        scans_this_month=int(row.get("scans_this_month") or 0),
    )


def get_subscription(client: SupabaseClient, token: str, org_id: str) -> tuple[Plan, str]:
    """The org's plan and subscription status.

    Returns the free plan when there is no row, or when the subscription has
    lapsed — otherwise cancelling would leave an org on its old limits forever.
    """
    rows = client.select(
        "subscriptions",
        token,
        params={
            "select": f"plan_id,status,plans({_PLAN_COLUMNS})",
            "org_id": f"eq.{org_id}",
            "limit": "1",
        },
    )
    if not rows:
        return FREE_PLAN, "none"
    row = rows[0]
    status = str(row.get("status") or "none")
    raw_plan = row.get("plans")
    if status not in _ENTITLING_STATUSES or not isinstance(raw_plan, dict):
        return FREE_PLAN, status
    return _plan(raw_plan), status


def entitlements(client: SupabaseClient, token: str, org_id: str) -> Entitlements:
    """What this org may do right now.

    A failure here opens the gate rather than closing it. Failing closed would
    let a billing outage stop a security team from scanning, which is a worse
    outcome than briefly allowing an org slightly over its limit — and the
    result says it is degraded so callers can surface that honestly.
    """
    try:
        plan, status = get_subscription(client, token, org_id)
        usage = get_usage(client, token, org_id)
    except SupabaseError as exc:
        return Entitlements(
            plan=FREE_PLAN,
            usage=Usage(0, 0, 0),
            status="unknown",
            degraded=True,
            error=str(exc),
        )
    return Entitlements(plan=plan, usage=usage, status=status)
