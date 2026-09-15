# 0003 — Separate parsing (loader) from detection (checks)

**Status:** Accepted

## Context
Prototype detectors each opened files themselves, mixed I/O with logic, and
threw unhandled exceptions on malformed input (a scalar YAML, a bad JSON, a
non-numeric field → HTTP 500). They were also impossible to unit test without
touching disk.

## Decision
One `loader` layer turns files into typed `Artifact` objects (kind + parsed
data). Checks receive an `Artifact` and are pure functions of it — no file I/O.
The `Engine` isolates every parse and every check in try/except: a bad file or a
throwing rule becomes a recorded error, never a crash.

## Consequences
- **+** Checks are trivially unit-testable with in-memory data.
- **+** One malformed file can't kill a scan of a 10k-file repo.
- **+** Live-cloud inputs (Phase 2) become "just another Artifact source" — the
  rules don't change at all.
- **−** An extra abstraction layer vs. calling `open()` in a check. Cheap.
