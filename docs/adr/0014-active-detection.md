# ADR 0014, Active detection (opt-in)

## Status
Accepted.

## Context
Passive assessment (ADR 0013) confirms posture but not exploitable bugs. Authorized
active testing, sending crafted probes to confirm a vulnerability exists, is what
OWASP ZAP, Burp Scanner, Nuclei, and SQLMap do on scoped engagements. The checklist
(PTES + OWASP WSTG) should resolve intrusive items with real evidence, not just list
them.

## Decision
Add an **opt-in active-detection** tier in `cloudnova.range.webassess.active`:

- It sends bounded probes to query parameters and inspects the response to confirm a
  finding: a unique marker for reflected XSS, a breaking token for SQL-error
  detection, a traversal payload for the `/etc/passwd` signature.
- Detection logic is pure functions; networking is isolated and scope-gated, so the
  ruleset is deterministic and testable offline.
- The checklist runner gains `active=True` (CLI `--active`), off by default. When on,
  active items flip from TODO to PASS/FAIL from real detection.
- Authorization is the gate: a scope file, or an explicit `--i-am-authorized "<name>"`
  self-attestation recorded in the report, is required before any probe is sent.

## Consequences
- Real DAST value: the product finds genuine vulnerabilities, not just posture.
- Each new active check is a pure detector + a scope-gated probe + a test.
- The severity/report pipeline is shared with the passive engine, so findings read
  consistently and roll into the engagement report.
