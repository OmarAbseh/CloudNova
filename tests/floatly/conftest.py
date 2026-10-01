"""Shared fixtures for the platform tests.

Everything runs through ``httpx.MockTransport``, so real request building,
header signing and response parsing are exercised — only the socket is faked.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest

pytest.importorskip("httpx")
import httpx

from cloudnova.platform.client import SupabaseClient
from cloudnova.platform.config import SupabaseConfig

CONFIG = SupabaseConfig(url="https://proj.supabase.co", anon_key="anon-key-123")


class Recorder:
    """Captures every request so tests can assert on who signed it."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    @property
    def last(self) -> httpx.Request:
        assert self.requests, "no request was made"
        return self.requests[-1]

    def bearer(self, index: int = -1) -> str:
        return self.requests[index].headers["Authorization"].removeprefix("Bearer ")

    def body(self, index: int = -1) -> Any:
        return json.loads(self.requests[index].content)

    def path(self, index: int = -1) -> str:
        return self.requests[index].url.path


@pytest.fixture
def config() -> SupabaseConfig:
    return CONFIG


@pytest.fixture
def make_client() -> Callable[..., tuple[SupabaseClient, Recorder]]:
    """Factory: give it a handler (or a list of responses), get a wired client."""

    def _factory(
        handler: Callable[[httpx.Request], httpx.Response] | list[httpx.Response],
    ) -> tuple[SupabaseClient, Recorder]:
        recorder = Recorder()
        queue = list(handler) if isinstance(handler, list) else None

        def _record(request: httpx.Request) -> httpx.Response:
            recorder.requests.append(request)
            if queue is not None:
                assert queue, f"unexpected extra request to {request.url}"
                return queue.pop(0)
            assert callable(handler)
            return handler(request)

        return SupabaseClient(CONFIG, transport=httpx.MockTransport(_record)), recorder

    return _factory


@pytest.fixture
def session_payload() -> Callable[..., dict[str, Any]]:
    def _build(**overrides: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "access_token": "user-jwt",
            "refresh_token": "refresh-xyz",
            "expires_in": 3600,
            "user": {"id": "user-1", "email": "omar@example.test"},
        }
        payload.update(overrides)
        return payload

    return _build
