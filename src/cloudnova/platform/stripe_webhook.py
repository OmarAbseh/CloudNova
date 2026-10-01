"""Stripe webhook: verify the signature, turn an event into a plan change.

A webhook endpoint is unauthenticated and publicly reachable, and what it
writes decides what a customer is entitled to. The signature is therefore the
entire security boundary, and this module treats it that way: no secret means
refuse, not skip; an old timestamp is a replay; and an event that does not say
which organization it belongs to is dropped rather than guessed at.

No Stripe SDK. The verification is a documented HMAC construction, and
implementing it directly keeps the dependency surface of a public endpoint
small and the logic testable without network or API keys.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cloudnova.platform.client import SupabaseClient

# Stripe's own default. A captured request stays replayable for this long, so
# it is a trade between clock skew tolerance and replay window.
_TOLERANCE_SECONDS = 300

# Stripe statuses mapped onto our subscription_status enum. Anything Stripe
# adds later lands on `incomplete` rather than being written through and
# breaking the insert — being wrong in the safe direction.
_STATUS_MAP = {
    "active": "active",
    "trialing": "trialing",
    "past_due": "past_due",
    "canceled": "canceled",
    "unpaid": "past_due",
    "incomplete": "incomplete",
    "incomplete_expired": "canceled",
}

# Plan ids that exist in migration 0004. An unrecognised price must not invent
# a plan id, because `subscriptions.plan_id` is a foreign key.
_KNOWN_PLANS = frozenset({"free", "pro", "enterprise"})

_SUBSCRIPTION_EVENTS = frozenset(
    {
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
    }
)


class SignatureError(ValueError):
    """The payload did not come from Stripe, or is too old to trust."""


@dataclass(frozen=True)
class StripeEvent:
    id: str
    type: str
    data: dict[str, Any]


@dataclass(frozen=True)
class PlanChange:
    """What to write to `subscriptions` as a result of one event."""

    org_id: str
    plan_id: str
    status: str
    stripe_customer_id: str
    stripe_subscription_id: str
    current_period_end: str | None
    cancel_at_period_end: bool


def _parse_header(header: str) -> tuple[int, list[str]]:
    timestamp: int | None = None
    signatures: list[str] = []
    for part in header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t":
            try:
                timestamp = int(value)
            except ValueError as exc:
                raise SignatureError("Malformed timestamp in signature header.") from exc
        elif key == "v1":
            # Several v1 values appear while a signing secret is being rotated.
            signatures.append(value)
    if timestamp is None or not signatures:
        raise SignatureError("Missing timestamp or signature in Stripe-Signature header.")
    return timestamp, signatures


def verify_signature(
    payload: bytes,
    header: str,
    secret: str,
    *,
    tolerance_seconds: int = _TOLERANCE_SECONDS,
) -> StripeEvent:
    """Check the signature and parse the event, or raise ``SignatureError``.

    An empty secret raises. Treating a missing secret as "verification off"
    would turn a misconfigured deployment into an open endpoint that anyone
    could use to grant themselves a plan.
    """
    if not secret:
        raise SignatureError("No webhook signing secret is configured.")
    if not header:
        raise SignatureError("Missing Stripe-Signature header.")

    timestamp, signatures = _parse_header(header)

    age = time.time() - timestamp
    if age > tolerance_seconds:
        raise SignatureError("Signature timestamp is too old.")

    signed = f"{timestamp}.".encode() + payload
    expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    # compare_digest against every candidate, and never short-circuit on the
    # first mismatch in a way that leaks which one matched.
    if not any(hmac.compare_digest(expected, candidate) for candidate in signatures):
        raise SignatureError("Signature does not match.")

    try:
        parsed = json.loads(payload)
    except ValueError as exc:
        raise SignatureError("Payload is signed but is not valid JSON.") from exc
    if not isinstance(parsed, dict):
        raise SignatureError("Payload is not a Stripe event object.")

    raw_data = parsed.get("data")
    obj = raw_data.get("object") if isinstance(raw_data, dict) else None
    return StripeEvent(
        id=str(parsed.get("id") or ""),
        type=str(parsed.get("type") or ""),
        data=obj if isinstance(obj, dict) else {},
    )


def _plan_id_from(subscription: dict[str, Any]) -> str:
    """Read the plan from the price's lookup key, then its metadata.

    Falls back to `free` rather than inventing an id: `plan_id` is a foreign
    key, so a guess would fail the insert and drop the event entirely.
    """
    raw_items = subscription.get("items")
    items = raw_items.get("data") if isinstance(raw_items, dict) else None
    if not isinstance(items, list) or not items:
        return "free"
    first: dict[str, Any] = items[0] if isinstance(items[0], dict) else {}
    raw_price = first.get("price")
    price: dict[str, Any] = raw_price if isinstance(raw_price, dict) else {}

    lookup = price.get("lookup_key")
    if isinstance(lookup, str) and lookup in _KNOWN_PLANS:
        return lookup

    raw_meta = price.get("metadata")
    metadata: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
    named = metadata.get("plan_id")
    if isinstance(named, str) and named in _KNOWN_PLANS:
        return named
    return "free"


def _period_end(subscription: dict[str, Any]) -> str | None:
    raw = subscription.get("current_period_end")
    if not isinstance(raw, (int, float)):
        return None
    return datetime.fromtimestamp(float(raw), tz=UTC).isoformat()


def plan_change_from_event(event: StripeEvent) -> PlanChange | None:
    """What this event means for an org, or ``None`` if it means nothing.

    Returning ``None`` is the normal path for most events — Stripe sends many
    kinds and only subscription changes matter here.
    """
    if event.type not in _SUBSCRIPTION_EVENTS:
        return None

    subscription = event.data
    raw_metadata = subscription.get("metadata")
    metadata: dict[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
    org_id = metadata.get("org_id")
    if not isinstance(org_id, str) or not org_id:
        # Nothing to apply this to. Guessing which tenant to bill would be far
        # worse than dropping the event and alerting a human.
        return None

    deleted = event.type == "customer.subscription.deleted"
    status = (
        "canceled" if deleted else _STATUS_MAP.get(str(subscription.get("status")), "incomplete")
    )
    plan_id = "free" if deleted else _plan_id_from(subscription)

    return PlanChange(
        org_id=org_id,
        plan_id=plan_id,
        status=status,
        stripe_customer_id=str(subscription.get("customer") or ""),
        stripe_subscription_id=str(subscription.get("id") or ""),
        current_period_end=_period_end(subscription),
        cancel_at_period_end=bool(subscription.get("cancel_at_period_end")),
    )


def apply_plan_change(client: SupabaseClient, service_role_key: str, change: PlanChange) -> None:
    """Write a plan change to `subscriptions`.

    This is the only function in the codebase that uses the service-role key,
    and it has to: `subscriptions` has no write policy and no write grant, so a
    credential that bypasses RLS is the only thing that can write it — which is
    exactly the property that stops a customer upgrading themselves.

    Because of that it runs in its own process (``cloudnova-billing``), so the
    key never has to be present in the dashboard's environment.
    """
    if not service_role_key:
        raise ValueError("A service-role key is required to write subscriptions.")
    row: dict[str, Any] = {
        "org_id": change.org_id,
        "plan_id": change.plan_id,
        "status": change.status,
        "stripe_customer_id": change.stripe_customer_id,
        "stripe_subscription_id": change.stripe_subscription_id,
        "cancel_at_period_end": change.cancel_at_period_end,
    }
    if change.current_period_end:
        row["current_period_end"] = change.current_period_end
    client.upsert("subscriptions", service_role_key, [row], on_conflict="org_id")
