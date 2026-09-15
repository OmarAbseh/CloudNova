# 0002 — Checks are plugins registered via a decorator

**Status:** Accepted

## Context
The prototype hard-coded three detector functions and called each by hand in
`app.py` and `main.py`. Adding a rule meant editing the orchestrator. That does
not scale to the hundreds of rules a real cloud scanner needs.

## Decision
A check is a `Check` subclass with metadata class attributes and a `run()`
method. A `@register` decorator adds an instance to a global `CheckRegistry` at
import time. The engine queries the registry by `target` (artifact kind) and
never imports a specific rule.

## Consequences
- **+** Adding a rule = one new class + one import line. The engine is untouched.
- **+** `__init_subclass__` rejects a check missing required metadata at import.
- **+** The registry rejects duplicate IDs, so a copy-paste rule fails fast.
- **−** Import-time side effects (registration) — mitigated by keeping the
  registry explicit and tested.

## Alternatives considered
- Entry-points / setuptools plugins: right for third-party packs, overkill for
  in-repo rules today. Revisit when external rule packs are a goal.
