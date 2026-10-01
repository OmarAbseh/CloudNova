# 0010 - IAM: author least-privilege, and audit for escalation

**Status:** Accepted

## Context
Detecting a wildcard IAM policy is useful, but two adjacent needs kept coming up:
*writing* a correctly-scoped policy in the first place, and *auditing* a policy
for the subtle privilege-escalation vectors a wildcard check misses (e.g.
`iam:PassRole` + `ec2:RunInstances`).

## Decision
Add a `cloudnova.iam` module with two halves:
- **generator** - turns a high-level grant spec ("read+list this bucket") into a
  least-privilege policy, refusing wildcard resources so its output is scoped by
  construction.
- **analyzer** - audits any policy for full/service wildcards, known
  privilege-escalation actions and combos, wildcard principals, and
  `NotAction`+Allow. Reuses the core `Finding` model, so it flows through the
  same reporting.

They are tied together by a round-trip test: the analyzer must report **zero**
findings on the generator's output. Exposed via `cloudnova iam generate/analyze`.

## Consequences
- **+** CloudNova is now an IAM *author*, not only an auditor.
- **+** The round-trip test makes "least privilege" a property we verify, not
  just claim.
- **+** Escalation combos encode real attacker techniques, not just wildcards.
- **−** The generator covers a curated set of services/access levels; unknown
  ones are a clear error rather than a guess. Extending it is a data-only change.
