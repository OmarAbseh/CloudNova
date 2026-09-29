"""Operator personas for Range — the identity the tool wears.

Range can present two faces, switchable and purely cosmetic:

- **cloudnova** — the professional product face, part of CloudNova's services.
- **gh0st** — the operator's personal handle.

A persona changes how the tool greets you and the default report byline. It has
no effect on any security behavior — the scope engine, checks, and gating are
identical whichever persona is active. Selection: the ``CLOUDNOVA_PERSONA`` env
var wins, else a saved choice in the config dir, else the default.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PERSONA = "cloudnova"


@dataclass(frozen=True)
class Persona:
    """A cosmetic operator identity."""

    id: str
    display_name: str
    handle: str
    tagline: str

    def banner(self) -> str:
        return f"{self.display_name} — {self.tagline}"


_PERSONAS: dict[str, Persona] = {
    "cloudnova": Persona(
        id="cloudnova",
        display_name="CloudNova Range",
        handle="operator",
        tagline="Authorized security testing, by the book.",
    ),
    "gh0st": Persona(
        id="gh0st",
        display_name="gh0st",
        handle="gh0st",
        tagline="In scope, on target, off the record.",
    ),
}


def _config_dir() -> Path:
    override = os.environ.get("CLOUDNOVA_CONFIG_DIR")
    return Path(override) if override else Path.home() / ".cloudnova"


def _persona_file() -> Path:
    return _config_dir() / "persona"


def list_personas() -> list[Persona]:
    return list(_PERSONAS.values())


def get_persona(persona_id: str) -> Persona | None:
    return _PERSONAS.get(persona_id.lower())


def active_persona() -> Persona:
    """Resolve the active persona: env var, then saved file, then default."""
    env = os.environ.get("CLOUDNOVA_PERSONA")
    if env and env.lower() in _PERSONAS:
        return _PERSONAS[env.lower()]
    try:
        saved = _persona_file().read_text(encoding="utf-8").strip().lower()
        if saved in _PERSONAS:
            return _PERSONAS[saved]
    except OSError:
        pass
    return _PERSONAS[DEFAULT_PERSONA]


def set_active(persona_id: str) -> Persona:
    """Persist the chosen persona; raises KeyError for an unknown id."""
    key = persona_id.lower()
    if key not in _PERSONAS:
        raise KeyError(f"Unknown persona {persona_id!r}. Available: {', '.join(_PERSONAS)}.")
    path = _persona_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(key + "\n", encoding="utf-8")
    return _PERSONAS[key]
