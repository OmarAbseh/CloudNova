# ADR 0014 — Active detection (opt-in), and the detection/weaponization line

## Status
Accepted.

## Context
Passive assessment (ADR 0013) is not enough to be a credible pentest tool.
Authorized active testing — sending crafted probes to confirm vulnerabilities — is
legal and is exactly what OWASP ZAP, Burp Scanner, Nuclei, and SQLMap do on scoped
engagements. The checklist (PTES + OWASP WSTG) needs to actually resolve intrusive
items, not just list them.

## Decision
Add an **opt-in active-detection** tier:

- `cloudnova.range.webassess.active` sends bounded, benign probes to query
  parameters and inspects the response to *confirm a bug exists*: a unique marker
  for reflected XSS, a breaking token for SQL-error detection, a traversal payload
  for the `/etc/passwd` signature. Detection logic is pure functions; networking is
  isolated and scope-gated.
- The checklist runner gains `active=True` (CLI `--active`). Off by default. When
  on, ACTIVE items flip from TODO to PASS/FAIL from real detection.
- Authorization stays the only gate. A scope file, or an explicit
  `--i-am-authorized "<name>"` self-attestation (recorded in the report), is
  required. Self-attestation is an accountability record, not a safety bypass.

## The line: detection, not weaponization
The tool **detects** and **reports**. It does not weaponize: no shells, no data
exfiltration, no destructive writes, no persistence, no pivoting, and nothing runs
unattended off a checkbox. Those remain operator-driven — the mentor teaches them,
the tool tracks them. This keeps the capability legal by construction and credible
to sell, while refusing the actual misuse vector (autonomous, unsupervised
exploitation against unverifiable "authorization").

## Consequences
- Real DAST value: the product can find genuine vulnerabilities, not just posture.
- Each new active check is a pure detector + a scope-gated probe + a test.
- The severity/report pipeline is shared with the passive engine, so findings read
  consistently and roll into the DarkShield-style report.
