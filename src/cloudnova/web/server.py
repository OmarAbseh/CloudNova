"""Entry point that runs the CloudNova web dashboard with uvicorn."""

from __future__ import annotations

import os


def main() -> None:
    """Run the dashboard. Binds to 127.0.0.1 by default (local operator tool)."""
    import uvicorn

    host = os.environ.get("CLOUDNOVA_WEB_HOST", "127.0.0.1")
    port = int(os.environ.get("CLOUDNOVA_WEB_PORT", "8000"))
    uvicorn.run("cloudnova.web.app:create_app", host=host, port=port, factory=True)


if __name__ == "__main__":
    main()
