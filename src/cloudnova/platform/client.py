"""A small, explicit Supabase client over httpx.

Deliberately not the ``supabase`` SDK. The whole security model here rests on
*which* credential signs each request, and a thin client makes that impossible
to get wrong by accident: every data call takes the end user's access token and
sends it as the bearer, so PostgREST evaluates Row-Level Security as that user.
There is no code path in this module that can talk to the database with
anything stronger.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

from cloudnova.platform.config import SupabaseConfig

_TIMEOUT = 10.0

# Refresh a little before the token actually expires so a request that is in
# flight when the clock crosses the boundary does not fail.
_EXPIRY_SKEW_SECONDS = 60


class SupabaseError(RuntimeError):
    """Any failure talking to Supabase."""


class AuthError(SupabaseError):
    """Sign-up/sign-in/refresh was rejected. Message is safe to show a user."""


@dataclass(frozen=True)
class Session:
    """An authenticated user session, as returned by GoTrue."""

    access_token: str
    refresh_token: str
    expires_at: float
    user_id: str
    email: str

    @property
    def expired(self) -> bool:
        return time.time() >= (self.expires_at - _EXPIRY_SKEW_SECONDS)


def _error_message(response: httpx.Response, fallback: str) -> str:
    """Pull a human-readable message out of GoTrue/PostgREST's several shapes."""
    try:
        payload = response.json()
    except ValueError:
        return fallback
    if isinstance(payload, dict):
        for key in ("error_description", "msg", "message", "error", "hint", "details"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return fallback


class SupabaseClient:
    """Auth + data access against one Supabase project.

    ``transport`` exists so tests can drive the full request-building and
    response-parsing path through ``httpx.MockTransport`` without a network.
    """

    def __init__(
        self,
        config: SupabaseConfig,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = _TIMEOUT,
    ) -> None:
        self.config = config
        self._http = httpx.Client(transport=transport, timeout=timeout)

    def close(self) -> None:
        self._http.close()

    # -- plumbing ---------------------------------------------------------

    def _headers(self, access_token: str | None = None) -> dict[str, str]:
        # `apikey` identifies the project; the bearer decides who you are. With
        # no user token the anon key is its own bearer, which RLS treats as the
        # `anon` role — and that role is granted nothing in 0001_platform.sql.
        return {
            "apikey": self.config.anon_key,
            "Authorization": f"Bearer {access_token or self.config.anon_key}",
            "Content-Type": "application/json",
        }

    def _request(
        self,
        method: str,
        url: str,
        *,
        access_token: str | None = None,
        json: Any | None = None,
        params: dict[str, str] | None = None,
        extra_headers: dict[str, str] | None = None,
        error_cls: type[SupabaseError] = SupabaseError,
        fallback: str = "Supabase request failed",
    ) -> Any:
        headers = self._headers(access_token)
        if extra_headers:
            headers.update(extra_headers)
        try:
            response = self._http.request(method, url, json=json, params=params, headers=headers)
        except httpx.HTTPError as exc:  # network down, DNS, timeout
            raise SupabaseError(f"Could not reach Supabase: {exc}") from exc
        if response.status_code >= 400:
            raise error_cls(_error_message(response, fallback))
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            return None

    # -- auth -------------------------------------------------------------

    def _session_from(self, payload: Any) -> Session | None:
        if not isinstance(payload, dict):
            return None
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            return None
        raw_user = payload.get("user")
        user: dict[str, Any] = raw_user if isinstance(raw_user, dict) else {}
        expires_in = payload.get("expires_in")
        expires_at = payload.get("expires_at")
        if isinstance(expires_at, (int, float)):
            absolute = float(expires_at)
        elif isinstance(expires_in, (int, float)):
            absolute = time.time() + float(expires_in)
        else:
            absolute = time.time() + 3600.0
        return Session(
            access_token=access_token,
            refresh_token=str(payload.get("refresh_token") or ""),
            expires_at=absolute,
            user_id=str(user.get("id") or ""),
            email=str(user.get("email") or ""),
        )

    def sign_up(self, email: str, password: str) -> Session | None:
        """Register an account.

        Returns ``None`` when the project requires email confirmation — the
        account exists but there is no session yet, which the caller must tell
        the user rather than treating as a failed sign-up.
        """
        payload = self._request(
            "POST",
            f"{self.config.auth_url}/signup",
            json={"email": email, "password": password},
            error_cls=AuthError,
            fallback="Could not create that account.",
        )
        return self._session_from(payload)

    def sign_in(self, email: str, password: str) -> Session:
        payload = self._request(
            "POST",
            f"{self.config.auth_url}/token",
            params={"grant_type": "password"},
            json={"email": email, "password": password},
            error_cls=AuthError,
            fallback="Invalid email or password.",
        )
        session = self._session_from(payload)
        if session is None:
            raise AuthError("Invalid email or password.")
        return session

    def refresh(self, refresh_token: str) -> Session:
        payload = self._request(
            "POST",
            f"{self.config.auth_url}/token",
            params={"grant_type": "refresh_token"},
            json={"refresh_token": refresh_token},
            error_cls=AuthError,
            fallback="Your session has expired. Please sign in again.",
        )
        session = self._session_from(payload)
        if session is None:
            raise AuthError("Your session has expired. Please sign in again.")
        return session

    def sign_out(self, access_token: str) -> None:
        """Revoke the session server-side. Best effort: a failure here must not
        stop us clearing the cookie, or a user could get stuck signed in."""
        try:
            self._request("POST", f"{self.config.auth_url}/logout", access_token=access_token)
        except SupabaseError:
            return

    def get_user(self, access_token: str) -> dict[str, Any]:
        """Resolve a token to its user. This is the authoritative check that a
        session cookie is real — we never trust the token's own contents."""
        payload = self._request(
            "GET",
            f"{self.config.auth_url}/user",
            access_token=access_token,
            error_cls=AuthError,
            fallback="Your session is no longer valid.",
        )
        if not isinstance(payload, dict) or not payload.get("id"):
            raise AuthError("Your session is no longer valid.")
        return payload

    # -- data (always as the user, so RLS applies) ------------------------

    def select(
        self,
        table: str,
        access_token: str,
        *,
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        payload = self._request(
            "GET",
            f"{self.config.rest_url}/{table}",
            access_token=access_token,
            params=params,
            fallback=f"Could not read {table}.",
        )
        return (
            [row for row in payload if isinstance(row, dict)] if isinstance(payload, list) else []
        )

    def insert(
        self,
        table: str,
        access_token: str,
        rows: list[dict[str, Any]],
        *,
        returning: bool = True,
    ) -> list[dict[str, Any]]:
        if not rows:
            return []
        prefer = "return=representation" if returning else "return=minimal"
        payload = self._request(
            "POST",
            f"{self.config.rest_url}/{table}",
            access_token=access_token,
            json=rows,
            extra_headers={"Prefer": prefer},
            fallback=f"Could not write to {table}.",
        )
        return (
            [row for row in payload if isinstance(row, dict)] if isinstance(payload, list) else []
        )
