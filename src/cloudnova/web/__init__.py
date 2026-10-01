"""CloudNova web dashboard - a local, browser-based view of the scanner and mentor.

A small FastAPI app (optional ``cloudnova[web]`` extra) that runs on localhost and
gives CloudNova a website face: run a scan and see findings, the posture score,
and attack paths in the browser; browse the pentest-mentor curriculum. It's a
local operator tool - it binds to 127.0.0.1 by default and reuses the same tested
engine, service, and Range modules as the CLI.
"""

from cloudnova.web.app import create_app

__all__ = ["create_app"]
