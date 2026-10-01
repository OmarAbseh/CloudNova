"""The Stripe webhook endpoint, as its own ASGI app and process.

Separate from the dashboard on purpose. Writing `subscriptions` needs the
service-role key, which bypasses Row-Level Security entirely — so if it lived
in the dashboard's environment, any bug in any dashboard route could reach
every tenant's data. Running the webhook alone means the key exists in one
small process that serves exactly one route.

That is also why ``cloudnova-web`` warns when it finds a service-role key: in
the intended deployment, it should never see one.
"""

from __future__ import annotations

import os
import sys
from typing import Any

from fastapi import FastAPI, Request, Response

from cloudnova.platform.client import SupabaseClient, SupabaseError
from cloudnova.platform.config import load_config
from cloudnova.platform.stripe_webhook import (
    SignatureError,
    apply_plan_change,
    plan_change_from_event,
    verify_signature,
)


def create_app() -> FastAPI:
    app = FastAPI(title="CloudNova billing", version="1")
    config = load_config()
    secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    service_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    client = SupabaseClient(config) if config else None

    @app.get("/health")
    def health() -> dict[str, Any]:
        # Report readiness without ever revealing the values.
        return {
            "status": "ok",
            "supabase_configured": client is not None,
            "signing_secret_configured": bool(secret),
            "service_key_configured": bool(service_key),
        }

    @app.post("/stripe/webhook")
    async def stripe_webhook(request: Request) -> Response:
        payload = await request.body()
        try:
            event = verify_signature(payload, request.headers.get("Stripe-Signature", ""), secret)
        except SignatureError:
            # Deliberately terse. A detailed reason would help someone probe
            # the endpoint, and Stripe does not need it.
            return Response("invalid signature", status_code=400)

        change = plan_change_from_event(event)
        if change is None:
            # Most Stripe events are not subscription changes. Acknowledge, or
            # Stripe retries them forever.
            return Response(status_code=204)

        if client is None or not service_key:
            # 500 so Stripe retries once the deployment is fixed, rather than
            # dropping a real billing change on the floor.
            return Response("billing backend not configured", status_code=500)

        try:
            apply_plan_change(client, service_key, change)
        except (SupabaseError, ValueError):
            return Response("could not apply change", status_code=500)
        return Response(status_code=204)

    return app


def main() -> None:
    """Run the webhook service."""
    import uvicorn

    if not os.environ.get("STRIPE_WEBHOOK_SECRET"):
        sys.exit(
            "Refusing to start without STRIPE_WEBHOOK_SECRET. Without it every "
            "payload would fail verification, and a webhook that cannot verify "
            "is worse than one that is not running."
        )
    port = int(os.environ.get("PORT") or os.environ.get("CLOUDNOVA_BILLING_PORT") or 8001)
    host = os.environ.get("CLOUDNOVA_BILLING_HOST", "127.0.0.1")
    uvicorn.run("cloudnova.web.billing_service:create_app", host=host, port=port, factory=True)


if __name__ == "__main__":
    main()
