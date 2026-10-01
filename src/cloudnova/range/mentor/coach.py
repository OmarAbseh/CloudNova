"""The coach: turns the curriculum into a personalised learning path.

Pure logic over :mod:`curriculum` - ordering modules by prerequisite, building
certification tracks, and mapping job levels to the skills employers expect. No
network, no LLM required; a Claude-backed "explain this deeper" layer can sit on
top later, but the structure and guidance are all here and fully testable.
"""

from __future__ import annotations

from dataclasses import dataclass

from cloudnova.range.mentor.curriculum import CURRICULUM, Level, Module, all_modules, get_module

# Certification tracks: the modules that prepare you for each exam. Grounded in
# each cert's published domains (methodology-level, not exam answers).
CERT_TRACKS: dict[str, list[str]] = {
    "eJPT": ["foundations", "methodology", "recon", "network-traffic", "web-owasp", "reporting"],
    "PNPT": [
        "foundations",
        "methodology",
        "recon",
        "web-owasp",
        "privesc-linux",
        "privesc-windows",
        "active-directory",
        "reporting",
    ],
    "OSCP": [
        "methodology",
        "recon",
        "web-owasp",
        "password-attacks",
        "privesc-linux",
        "privesc-windows",
        "active-directory",
        "reporting",
    ],
    "CEH": ["foundations", "methodology", "recon", "burp-suite", "web-owasp", "network-traffic"],
    "eWPT": ["burp-suite", "web-owasp", "reporting"],
}

# What each hiring level typically expects. Used to show readiness gaps.
JOB_LEVELS: dict[str, list[str]] = {
    "junior": ["foundations", "methodology", "recon", "burp-suite", "web-owasp", "reporting"],
    "mid": [
        "recon",
        "burp-suite",
        "web-owasp",
        "network-traffic",
        "password-attacks",
        "privesc-linux",
        "privesc-windows",
        "reporting",
    ],
    "senior": [m.id for m in CURRICULUM],  # seniors are expected to span the whole tree
}

_LEVEL_ORDER = {
    Level.FOUNDATION: 0,
    Level.JUNIOR: 1,
    Level.INTERMEDIATE: 2,
    Level.SENIOR: 3,
}


@dataclass(frozen=True)
class LearningStep:
    order: int
    module: Module


def learning_path(target_level: Level | None = None) -> list[LearningStep]:
    """Return modules ordered so prerequisites always come first (topological).

    Ties are broken by career level then id, so the path reads as a sensible
    beginner-to-advanced progression. ``target_level`` caps how far it goes.
    """
    cap = _LEVEL_ORDER[target_level] if target_level else max(_LEVEL_ORDER.values())
    modules = [m for m in all_modules() if _LEVEL_ORDER[m.level] <= cap]
    ordered: list[Module] = []
    placed: set[str] = set()

    def ready(m: Module) -> bool:
        return all(p in placed or get_module(p) is None for p in m.prereqs)

    remaining = list(modules)
    while remaining:
        batch = [m for m in remaining if ready(m)]
        if not batch:  # prereq cycle or out-of-cap prereq - emit the rest as-is
            batch = remaining
        batch.sort(key=lambda m: (_LEVEL_ORDER[m.level], m.id))
        for m in batch:
            ordered.append(m)
            placed.add(m.id)
        remaining = [m for m in remaining if m.id not in placed]
    return [LearningStep(i + 1, m) for i, m in enumerate(ordered)]


def cert_track(cert: str) -> list[Module]:
    """Return the modules that prepare you for ``cert`` (prereq-ordered)."""
    key = _resolve(cert, CERT_TRACKS)
    wanted = set(CERT_TRACKS[key])
    return [step.module for step in learning_path() if step.module.id in wanted]


def job_track(level: str) -> list[Module]:
    """Return the modules a hiring ``level`` expects (prereq-ordered)."""
    key = level.lower()
    if key not in JOB_LEVELS:
        raise KeyError(f"Unknown job level {level!r}. Choose from: {', '.join(JOB_LEVELS)}.")
    wanted = set(JOB_LEVELS[key])
    return [step.module for step in learning_path() if step.module.id in wanted]


def certs_for(module_id: str) -> list[str]:
    """Which cert tracks include this module."""
    return [cert for cert, ids in CERT_TRACKS.items() if module_id in ids]


def _resolve(name: str, table: dict[str, list[str]]) -> str:
    for key in table:
        if key.lower() == name.lower():
            return key
    raise KeyError(f"Unknown cert {name!r}. Available: {', '.join(table)}.")
