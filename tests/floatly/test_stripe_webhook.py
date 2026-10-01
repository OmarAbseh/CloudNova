"""Stripe webhook: signature verification and event handling.

Written before the implementation. A webhook endpoint is an unauthenticated,
publicly-reachable route that changes what customers are entitled to, so the
signature check is the whole security boundary and most of these tests are
about refusing things.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest

from cloudnova.platform.stripe_webhook import (
    SignatureError,
    StripeEvent,
    plan_change_from_event,
    verify_signature,
)

SECRET = "whsec_test_abc123"


def _sign(payload: bytes, secret: str = SECRET, timestamp: int | None = None) -> str:
    ts = int(time.time()) if timestamp is None else timestamp
    signed = f"{ts}.".encode() + payload
    sig = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


def _event(kind: str, data: dict) -> bytes:
    return json.dumps({"id": "evt_1", "type": kind, "data": {"object": data}}).encode()


# -- signature -------------------------------------------------------------


def test_a_correctly_signed_payload_is_accepted():
    body = _event("customer.subscription.updated", {})
    event = verify_signature(body, _sign(body), SECRET)
    assert isinstance(event, StripeEvent)
    assert event.type == "customer.subscription.updated"


def test_a_tampered_payload_is_rejected():
    body = _event("customer.subscription.updated", {})
    header = _sign(body)
    tampered = body.replace(b"updated", b"deleted")
    with pytest.raises(SignatureError):
        verify_signature(tampered, header, SECRET)


def test_the_wrong_secret_is_rejected():
    body = _event("customer.subscription.updated", {})
    with pytest.raises(SignatureError):
        verify_signature(body, _sign(body, secret="whsec_someone_else"), SECRET)


def test_a_missing_header_is_rejected():
    with pytest.raises(SignatureError):
        verify_signature(b"{}", "", SECRET)


def test_a_malformed_header_is_rejected():
    with pytest.raises(SignatureError):
        verify_signature(b"{}", "not-a-signature-header", SECRET)


def test_an_old_timestamp_is_rejected_as_a_replay():
    # A captured request must not stay valid forever.
    body = _event("customer.subscription.updated", {})
    old = _sign(body, timestamp=int(time.time()) - 3600)
    with pytest.raises(SignatureError, match="too old"):
        verify_signature(body, old, SECRET)


def test_a_timestamp_inside_the_tolerance_is_accepted():
    body = _event("customer.subscription.updated", {})
    recent = _sign(body, timestamp=int(time.time()) - 60)
    assert verify_signature(body, recent, SECRET).type


def test_an_empty_secret_refuses_rather_than_accepting_everything():
    # A missing secret must never mean "skip the check".
    body = _event("customer.subscription.updated", {})
    with pytest.raises(SignatureError):
        verify_signature(body, _sign(body), "")


def test_signature_comparison_handles_multiple_v1_values():
    # Stripe sends several v1 signatures while a secret is being rotated.
    body = _event("customer.subscription.updated", {})
    real = _sign(body).split("v1=")[1]
    ts = _sign(body).split(",")[0]
    header = f"{ts},v1=deadbeef,v1={real}"
    assert verify_signature(body, header, SECRET).type


def test_invalid_json_is_rejected_even_when_signed():
    body = b"not json at all"
    with pytest.raises(SignatureError):
        verify_signature(body, _sign(body), SECRET)


# -- events to plan changes ------------------------------------------------


def test_subscription_updated_maps_to_a_plan_change():
    event = StripeEvent(
        id="evt_1",
        type="customer.subscription.updated",
        data={
            "id": "sub_123",
            "customer": "cus_123",
            "status": "active",
            "cancel_at_period_end": False,
            "current_period_end": 1790000000,
            "metadata": {"org_id": "org-1"},
            "items": {"data": [{"price": {"lookup_key": "pro"}}]},
        },
    )
    change = plan_change_from_event(event)
    assert change is not None
    assert change.org_id == "org-1"
    assert change.plan_id == "pro"
    assert change.status == "active"
    assert change.stripe_subscription_id == "sub_123"
    assert change.stripe_customer_id == "cus_123"
    assert change.current_period_end.startswith("2026-")


def test_a_deleted_subscription_becomes_canceled_on_free():
    event = StripeEvent(
        id="evt_2",
        type="customer.subscription.deleted",
        data={
            "id": "sub_123",
            "customer": "cus_123",
            "status": "canceled",
            "metadata": {"org_id": "org-1"},
            "items": {"data": [{"price": {"lookup_key": "pro"}}]},
        },
    )
    change = plan_change_from_event(event)
    assert change is not None
    assert change.status == "canceled"
    assert change.plan_id == "free"


def test_an_event_without_an_org_is_ignored():
    # Without org_id in metadata there is nothing to apply the change to, and
    # guessing which tenant to bill is far worse than dropping the event.
    event = StripeEvent(
        id="evt_3",
        type="customer.subscription.updated",
        data={"id": "sub_1", "customer": "cus_1", "status": "active", "metadata": {}},
    )
    assert plan_change_from_event(event) is None


def test_an_unrelated_event_is_ignored():
    event = StripeEvent(id="evt_4", type="invoice.paid", data={})
    assert plan_change_from_event(event) is None


def test_an_unknown_lookup_key_falls_back_to_free_rather_than_guessing():
    event = StripeEvent(
        id="evt_5",
        type="customer.subscription.updated",
        data={
            "id": "sub_1",
            "customer": "cus_1",
            "status": "active",
            "metadata": {"org_id": "org-1"},
            "items": {"data": [{"price": {"lookup_key": "some-new-price"}}]},
        },
    )
    change = plan_change_from_event(event)
    assert change is not None
    assert change.plan_id == "free"


def test_price_metadata_can_name_the_plan_when_no_lookup_key():
    event = StripeEvent(
        id="evt_6",
        type="customer.subscription.updated",
        data={
            "id": "sub_1",
            "customer": "cus_1",
            "status": "active",
            "metadata": {"org_id": "org-1"},
            "items": {"data": [{"price": {"metadata": {"plan_id": "enterprise"}}}]},
        },
    )
    change = plan_change_from_event(event)
    assert change is not None
    assert change.plan_id == "enterprise"


def test_an_unmapped_stripe_status_is_not_invented():
    # subscriptions.status is an enum; an unexpected value must not be written
    # through and blow up the insert.
    event = StripeEvent(
        id="evt_7",
        type="customer.subscription.updated",
        data={
            "id": "sub_1",
            "customer": "cus_1",
            "status": "paused",
            "metadata": {"org_id": "org-1"},
            "items": {"data": [{"price": {"lookup_key": "pro"}}]},
        },
    )
    change = plan_change_from_event(event)
    assert change is not None
    assert change.status == "incomplete"


# -- applying a change -----------------------------------------------------


def test_apply_upserts_the_subscription(make_client):
    import httpx

    from cloudnova.platform.stripe_webhook import PlanChange, apply_plan_change

    client, rec = make_client([httpx.Response(201, content=b"")])
    change = PlanChange(
        org_id="org-1",
        plan_id="pro",
        status="active",
        stripe_customer_id="cus_1",
        stripe_subscription_id="sub_1",
        current_period_end="2026-12-01T00:00:00+00:00",
        cancel_at_period_end=False,
    )
    apply_plan_change(client, "service-role-key", change)

    assert rec.path() == "/rest/v1/subscriptions"
    assert rec.last.url.params["on_conflict"] == "org_id"
    assert "merge-duplicates" in rec.last.headers["Prefer"]
    body = rec.body()[0]
    assert body["org_id"] == "org-1"
    assert body["plan_id"] == "pro"
    assert body["status"] == "active"
    assert body["stripe_subscription_id"] == "sub_1"


def test_apply_uses_the_service_role_key_not_a_user_token(make_client):
    # subscriptions has no write policy at all, so only a bypassing credential
    # can write it. This is the one place that is true, and it is why the
    # webhook runs as its own process.
    import httpx

    from cloudnova.platform.stripe_webhook import PlanChange, apply_plan_change

    client, rec = make_client([httpx.Response(201, content=b"")])
    apply_plan_change(
        client,
        "service-role-key",
        PlanChange("org-1", "pro", "active", "cus_1", "sub_1", None, False),
    )
    assert rec.bearer() == "service-role-key"


def test_apply_refuses_without_a_key(make_client):
    from cloudnova.platform.stripe_webhook import PlanChange, apply_plan_change

    client, rec = make_client([])
    with pytest.raises(ValueError, match="service-role"):
        apply_plan_change(client, "", PlanChange("org-1", "pro", "active", "c", "s", None, False))
    assert rec.requests == []
