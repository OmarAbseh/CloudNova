"""Entry point that runs the CloudNova web dashboard with uvicorn."""

from __future__ import annotations

import os
import sys


def _resolve_port() -> int:
    # Hosts like Render/Railway/Heroku inject $PORT; fall back to our own var, then 8000.
    for key in ("PORT", "CLOUDNOVA_WEB_PORT"):
        value = os.environ.get(key)
        if value:
            return int(value)
    return 8000


def main() -> None:
    """Run the dashboard.

    Binds 127.0.0.1 by default (local operator tool). Binding a public
    interface (e.g. 0.0.0.0 for hosting) REQUIRES the Floatly Platform to be
    configured, because that is what supplies accounts and per-org isolation.
    Without it the dashboard has no authentication at all, so exposing it would
    hand every visitor the scanner.
    """
    import uvicorn

    from cloudnova.platform.config import load_config, service_role_key_present

    host = os.environ.get("CLOUDNOVA_WEB_HOST", "127.0.0.1")
    port = _resolve_port()

    public = host not in ("127.0.0.1", "localhost", "::1")
    if public and load_config() is None:
        sys.exit(
            "Refusing to bind a public interface without authentication. "
            "Set SUPABASE_URL and SUPABASE_ANON_KEY to enable accounts and "
            "per-organization isolation first."
        )

    if service_role_key_present():
        # The dashboard never uses it, and it bypasses RLS - so if a route ever
        # picked it up by mistake, tenant isolation would be gone with no error.
        print(
            "warning: SUPABASE_SERVICE_ROLE_KEY is set in this process. The "
            "dashboard never uses it and it bypasses Row-Level Security; "
            "prefer keeping it out of the web environment.",
            file=sys.stderr,
        )

    uvicorn.run("cloudnova.web.app:create_app", host=host, port=port, factory=True)


if __name__ == "__main__":
    main()
