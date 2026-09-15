# CloudNova — working notes for contributors (human or AI)

## What this is
A cloud security scanning engine. `src/cloudnova/` is the real codebase;
`legacy/` is the archived thesis prototype (do not build on it).

## Layout
- `core/findings.py` — the `Finding` contract. Everything depends on it.
- `core/check.py` — `Check` base + `@register` + `CheckRegistry`.
- `core/loader.py` — the ONLY place that touches the filesystem.
- `core/engine.py` — orchestration; isolates every error.
- `checks/` — one module per rule pack; register in `checks/__init__.py`.
- `reporting/` — console + JSON formatters.
- `docs/adr/` — every design decision, numbered.

## Invariants (do not violate)
1. Checks are pure functions of an `Artifact` — no file I/O in a check.
2. A malformed input is a recorded error, never a crash.
3. Every finding is a validated `Finding`; no ad-hoc dicts.
4. Severity (how bad) and confidence (how sure) are separate.
5. New behavior ⇒ tests. New check ⇒ positive + negative test.

## Dev gate (all must pass; CI enforces)
```bash
ruff check src tests && ruff format --check src tests && mypy && pytest --cov=cloudnova
```

## Roadmap
See ROADMAP.md. Current: Phase 0 done; next is Phase 1 (Terraform/CFN/K8s).
