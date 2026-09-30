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

    Binds 127.0.0.1 by default (local operator tool). Binding a public interface
    (e.g. 0.0.0.0 for hosting) REQUIRES CLOUDNOVA_WEB_PASSWORD so the dashboard is
    never exposed unauthenticated.
    """
    import uvicorn

    host = os.environ.get("CLOUDNOVA_WEB_HOST", "127.0.0.1")
    port = _resolve_port()

    public = host not in ("127.0.0.1", "localhost", "::1")
    if public and not os.environ.get("CLOUDNOVA_WEB_PASSWORD"):
        sys.exit(
            "Refusing to bind a public interface without auth. "
            "Set CLOUDNOVA_WEB_PASSWORD (and optionally CLOUDNOVA_WEB_USER) first."
        )

    uvicorn.run("cloudnova.web.app:create_app", host=host, port=port, factory=True)


if __name__ == "__main__":
    main()
