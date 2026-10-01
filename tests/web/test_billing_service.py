"""The webhook endpoint: what it accepts, refuses, and tells Stripe.

The status codes matter as much as the behaviour — Stripe retries on 5xx and
gives up on 4xx, so getting them the wrong way round either drops real billing
changes or retries garbage forever.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
import httpx
from fastapi.testclient import TestClient

from cloudnova.platform.client import SupabaseClient
from cloudnova.platform.config import SupabaseConfig
from cloudnova.web import billing_service

SECRET = "whsec_test_abc123"
CONFIG = SupabaseConfig(url="https://proj.supabase.co", anon_key="anon-key")


def _sign(payload: bytes, secret: str = SECRET) -> str:
    ts = int(time.time())
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


def _subscription_event(org_id="org-1", plan="pro"):
    return json.dumps(
        {
            "id": "evt_1",
            "type": "customer.subscription.updated",
            "data": {
                "object": {
                    "id": "sub_1",
                    "customer": "cus_1",
                    "status": "active",
                    "metadata": {"org_id": org_id},
                    "items": {"data": [{"price": {"lookup_key": plan}}]},
                }
            },
        }
    ).encode()


@pytest.fixture
def service(monkeypatch):
    """The webhook app with a fake Supabase and a known signing secret."""

    def _build(*, secret=SECRET, service_key="service-role-key", responder=None):
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            if responder is not None:
                return responder(request)
            return httpx.Response(201, content=b"")

        monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", secret)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", service_key)
        monkeypatch.setattr(billing_service, "load_config", lambda: CONFIG)
        monkeypatch.setattr(
            billing_service,
            "SupabaseClient",
            lambda cfg: SupabaseClient(cfg, transport=httpx.MockTransport(handler)),
        )
        return TestClient(billing_service.create_app()), seen

    return _build


def test_a_valid_event_is_applied(service):
    app, seen = service()
    body = _subscription_event()
    r = app.post("/stripe/webhook", content=body, headers={"Stripe-Signature": _sign(body)})
    assert r.status_code == 204
    writes = [s for s in seen if s.url.path == "/rest/v1/subscriptions"]
    assert writes
    row = json.loads(writes[0].content)[0]
    assert row["org_id"] == "org-1"
    assert row["plan_id"] == "pro"


def test_the_write_uses_the_service_role_key(service):
    app, seen = service()
    body = _subscription_event()
    app.post("/stripe/webhook", content=body, headers={"Stripe-Signature": _sign(body)})
    assert seen[0].headers["Authorization"] == "Bearer service-role-key"


def test_an_unsigned_request_is_refused(service):
    app, seen = service()
    r = app.post("/stripe/webhook", content=_subscription_event())
    assert r.status_code == 400
    assert not seen  # nothing was written


def test_a_forged_signature_is_refused(service):
    app, seen = service()
    body = _subscription_event()
    r = app.post(
        "/stripe/webhook",
        content=body,
        headers={"Stripe-Signature": _sign(body, secret="whsec_attacker")},
    )
    assert r.status_code == 400
    assert not seen


def test_the_refusal_does_not_explain_itself(service):
    # A detailed reason would help someone probe the endpoint.
    app, _ = service()
    r = app.post("/stripe/webhook", content=b"{}", headers={"Stripe-Signature": "t=1,v1=bad"})
    assert r.status_code == 400
    assert "timestamp" not in r.text.lower()
    assert "secret" not in r.text.lower()


def test_an_irrelevant_event_is_acknowledged_not_retried(service):
    # 2xx, or Stripe retries every invoice.paid forever.
    app, seen = service()
    body = json.dumps({"id": "evt_2", "type": "invoice.paid", "data": {"object": {}}}).encode()
    r = app.post("/stripe/webhook", content=body, headers={"Stripe-Signature": _sign(body)})
    assert r.status_code == 204
    assert not seen


def test_an_event_without_an_org_is_acknowledged_not_retried(service):
    app, seen = service()
    body = _subscription_event(org_id="")
    r = app.post("/stripe/webhook", content=body, headers={"Stripe-Signature": _sign(body)})
    assert r.status_code == 204
    assert not seen


def test_a_database_failure_asks_stripe_to_retry(service):
    # 5xx on purpose: a real billing change must not be dropped because the
    # database blipped.
    app, _ = service(responder=lambda r: httpx.Response(500, json={"message": "down"}))
    body = _subscription_event()
    r = app.post("/stripe/webhook", content=body, headers={"Stripe-Signature": _sign(body)})
    assert r.status_code == 500


def test_a_missing_service_key_asks_stripe_to_retry(service):
    app, seen = service(service_key="")
    body = _subscription_event()
    r = app.post("/stripe/webhook", content=body, headers={"Stripe-Signature": _sign(body)})
    assert r.status_code == 500
    assert not seen


def test_health_reports_readiness_without_leaking_values(service):
    app, _ = service()
    r = app.get("/health")
    assert r.status_code == 200
    payload = r.json()
    assert payload["signing_secret_configured"] is True
    assert payload["service_key_configured"] is True
    # Booleans only — never the values themselves.
    assert SECRET not in r.text
    assert "service-role-key" not in r.text
