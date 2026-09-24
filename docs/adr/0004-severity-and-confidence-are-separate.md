# 0004 — Severity and confidence are independent axes

**Status:** Accepted

## Context
The prototype's S3 check flagged any bucket whose *name* contained "public" —
a guess dressed up as a High-severity fact. It had no way to say "this is bad IF
it's real, but I'm not sure it's real."

## Decision
Every finding carries both `severity` (how bad if true) and `confidence` (how
sure we are it's true). A name-based heuristic is HIGH severity / LOW confidence;
parsing an IAM policy document and seeing `Action:"*"` is HIGH/HIGH.

## Consequences
- **+** Consumers can filter noise (`confidence >= medium`) without losing the
  severity signal.
- **+** Honest output — the scanner stops crying wolf, which is the fastest way a
  security tool loses its users' trust.
- **−** Rule authors must think about confidence. That's a feature.
