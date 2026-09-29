# 0001 — A single typed `Finding` is the core contract

**Status:** Accepted

## Context
The prototype passed security results around as ad-hoc dicts (`{"threat":...,
"severity":...}`). Keys drifted between detectors, the PDF exporter crashed on a
missing `type` key, and nothing could be validated. Every output format
re-guessed the shape.

## Decision
Define one immutable, validated `Finding` (Pydantic v2) that **every** check
must produce. Severity and confidence are enums; location, remediation, and
compliance mappings (CIS/MITRE) are first-class fields.

## Consequences
- **+** One schema → any formatter (console/JSON/SARIF), diffable scans, a stable
  shape to feed an AI agent later.
- **+** Invalid findings fail loudly at construction, not at render time.
- **+** `frozen=True` makes findings safe to cache and pass across threads.
- **−** Slightly more ceremony to emit a finding than a bare dict. Worth it.

## Alternatives considered
- `@dataclass`: no validation, no JSON schema, no coercion. Rejected.
- `TypedDict`: static-only; nothing enforced at runtime. Rejected.
