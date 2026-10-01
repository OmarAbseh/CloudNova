"""Track learning progress so the Mentor knows where you are.

Persists which curriculum modules you've completed (in the config dir, like the
persona) and uses that to tell you what to do next - the next module whose
prerequisites you've already finished. This is what turns a static curriculum into
a companion that walks with you.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from cloudnova.range.mentor.coach import learning_path
from cloudnova.range.mentor.curriculum import Module, all_modules, get_module


def _config_dir() -> Path:
    override = os.environ.get("CLOUDNOVA_CONFIG_DIR")
    return Path(override) if override else Path.home() / ".cloudnova"


def _progress_file() -> Path:
    return _config_dir() / "progress.json"


def completed() -> set[str]:
    """The set of completed module ids (unknown ids are ignored)."""
    try:
        data = json.loads(_progress_file().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    valid = {m.id for m in all_modules()}
    return {mid for mid in data.get("completed", []) if mid in valid}


def _save(done: set[str]) -> None:
    path = _progress_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"completed": sorted(done)}, indent=2), encoding="utf-8")


def mark_done(module_id: str) -> Module:
    """Mark a module complete; raises KeyError for an unknown id."""
    module = get_module(module_id)
    if module is None:
        raise KeyError(module_id)
    done = completed()
    done.add(module.id)
    _save(done)
    return module


def mark_undone(module_id: str) -> None:
    done = completed()
    done.discard(module_id)
    _save(done)


def reset() -> None:
    _save(set())


@dataclass(frozen=True)
class Progress:
    done: int
    total: int

    @property
    def percent(self) -> int:
        return round(100 * self.done / self.total) if self.total else 0


def summary() -> Progress:
    return Progress(done=len(completed()), total=len(all_modules()))


def next_modules(count: int = 1) -> list[Module]:
    """Return the next modules to study: not done, and all prereqs already done."""
    done = completed()
    out: list[Module] = []
    for step in learning_path():
        m = step.module
        if m.id in done:
            continue
        if all(p in done or get_module(p) is None for p in m.prereqs):
            out.append(m)
        if len(out) >= count:
            break
    return out
