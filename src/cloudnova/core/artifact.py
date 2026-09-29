"""Parsed inputs that checks run against.

The engine turns a file on disk into one or more :class:`Artifact` objects,
each tagged with a ``kind`` (matching a check's ``target``). Separating
*parsing* from *checking* means a check never touches the filesystem — it just
inspects already-parsed, typed data. That keeps checks pure and testable, and
lets us later feed artifacts from a live cloud API instead of files with zero
change to the rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Artifact:
    """One parsed unit of input.

    ``data`` is the structured content (a dict for YAML/JSON configs); ``path``
    is where it came from (for finding locations); ``kind`` selects which
    checks apply.
    """

    kind: str
    path: str
    data: Any
    raw: str = ""
    meta: dict[str, Any] = field(default_factory=dict)
