"""CloudNova Range — authorized security testing.

A "range" is a place you are cleared to fire. This package is the offensive /
validation side of CloudNova, and it is built authorization-first: the ONLY entry
point is the scope engine, which decides whether a target is authorized before
any other capability may act on it.

Nothing here attacks anything on its own. The scope engine is a deny-by-default
policy gate — the professional foundation that makes everything built on top of it
legitimate. Future capabilities (recon organization, finding validation, a
practice-lab tutor) all consult :func:`authorize` first and refuse out-of-scope
targets.
"""

from cloudnova.range.persona import (
    Persona,
    active_persona,
    get_persona,
    list_personas,
    set_active,
)
from cloudnova.range.recon import ReconInventory, ReconParseError, organize
from cloudnova.range.report import Engagement, engagement_from_dict, render_markdown
from cloudnova.range.scope import (
    Authorization,
    Decision,
    Scope,
    ScopeError,
    authorize,
    load_scope,
)

__all__ = [
    "Authorization",
    "Decision",
    "Engagement",
    "Persona",
    "ReconInventory",
    "ReconParseError",
    "Scope",
    "ScopeError",
    "active_persona",
    "authorize",
    "engagement_from_dict",
    "get_persona",
    "list_personas",
    "load_scope",
    "organize",
    "render_markdown",
    "set_active",
]
