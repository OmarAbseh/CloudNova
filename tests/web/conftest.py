"""Fixtures that pin the dashboard's mode explicitly.

``create_app`` reads SUPABASE_* from the environment and falls back to the
repo's ``.env``. That is right for an operator and wrong for a test suite: it
would make results depend on whether the developer happens to have a project
configured. Every test here therefore states which mode it wants.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
import httpx
from fastapi.testclient import TestClient

from cloudnova.platform.client import SupabaseClient
from cloudnova.platform.config import SupabaseConfig
from cloudnova.web import app as app_module
from cloudnova.web import create_app

CONFIG = SupabaseConfig(url="https://proj.supabase.co", anon_key="anon-key-123")


@pytest.fixture(autouse=True)
def _no_ambient_platform(monkeypatch):
    """Never let a real .env or environment leak into a test."""
    monkeypatch.setattr(app_module, "load_config", lambda: None)


@pytest.fixture
def client():
    """The dashboard in local single-user mode: no accounts, nothing persisted."""
    return TestClient(create_app())


@pytest.fixture
def platform_app() -> Callable[..., tuple[TestClient, list[httpx.Request]]]:
    """The dashboard wired to a fake Supabase.

    ``handler`` receives each request and returns a response, so a test can
    model sign-in, an expired token, an RLS denial, or an outage.
    """

    def _build(
        handler: Callable[[httpx.Request], httpx.Response],
    ) -> tuple[TestClient, list[httpx.Request]]:
        seen: list[httpx.Request] = []

        def _record(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return handler(request)

        supa = SupabaseClient(CONFIG, transport=httpx.MockTransport(_record))
        return TestClient(create_app(supa)), seen

    return _build


def session_json(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "access_token": "user-jwt",
        "refresh_token": "refresh-xyz",
        "expires_in": 3600,
        "user": {"id": "user-1", "email": "omar@example.test"},
    }
    payload.update(overrides)
    return payload
