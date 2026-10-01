"""Configuration for the Floatly Platform backend (Supabase).

The dashboard has two legitimate modes and this module is what distinguishes
them. With ``SUPABASE_URL`` and ``SUPABASE_ANON_KEY`` set, the app runs
multi-tenant: real accounts, real orgs, every row filtered by RLS. Without
them it stays the single-user local operator tool it has always been. Returning
``None`` rather than raising is what keeps that second mode working.

Only the *anon* key belongs here. It is safe to ship to a browser precisely
because it carries no authority of its own — every request made with it is
still filtered by Row-Level Security. The service-role key bypasses RLS
entirely and must never reach this process; see ``load_config``.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

# Read from the repo's .env when present so operators have one place for
# secrets. Real environment variables always win: a hosting platform's config
# must never be silently overridden by a stale file in the working directory.
_ENV_FILE = ".env"


@dataclass(frozen=True)
class SupabaseConfig:
    """Everything needed to talk to a Supabase project as an end user."""

    url: str
    anon_key: str

    @property
    def auth_url(self) -> str:
        return f"{self.url}/auth/v1"

    @property
    def rest_url(self) -> str:
        return f"{self.url}/rest/v1"


def load_env_file(path: str | Path = _ENV_FILE) -> dict[str, str]:
    """Parse a dotenv file into a dict. Missing file yields an empty dict.

    Deliberately tiny: ``KEY=value`` lines, ``#`` comments, optional surrounding
    quotes. Anything fancier belongs in the hosting platform's own config.
    """
    file = Path(path)
    if not file.is_file():
        return {}
    values: dict[str, str] = {}
    for raw in file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def load_config(
    env: Mapping[str, str] | None = None,
    *,
    env_file: str | Path = _ENV_FILE,
) -> SupabaseConfig | None:
    """Build config from the environment, falling back to ``.env``.

    Returns ``None`` when the project is not configured, which the dashboard
    reads as "stay in local single-user mode".
    """
    source = os.environ if env is None else env
    file_values = load_env_file(env_file)

    def _get(key: str) -> str:
        return (source.get(key) or file_values.get(key) or "").strip()

    url = _get("SUPABASE_URL").rstrip("/")
    anon_key = _get("SUPABASE_ANON_KEY")
    if not url or not anon_key:
        return None
    return SupabaseConfig(url=url, anon_key=anon_key)


def service_role_key_present(
    env: Mapping[str, str] | None = None,
    *,
    env_file: str | Path = _ENV_FILE,
) -> bool:
    """True when a service-role key is reachable from this process.

    The dashboard never uses it — it bypasses RLS, so a bug in a route would
    become a cross-tenant data leak instead of an empty page. This exists so
    the app can warn an operator that the key is in scope needlessly.
    """
    source = os.environ if env is None else env
    file_values = load_env_file(env_file)
    return bool(
        (
            source.get("SUPABASE_SERVICE_ROLE_KEY")
            or file_values.get("SUPABASE_SERVICE_ROLE_KEY")
            or ""
        ).strip()
    )
