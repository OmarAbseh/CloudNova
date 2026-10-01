# ADR 0013, Authorized web assessment (passive, scope-gated)

## Status
Accepted.

## Context
CloudNova Range needed a target-facing capability beyond recon organization: an
assessment that actually talks to a live web target and reports its security
posture. The risk is obvious, a target-facing tool must not become an
unsupervised attack engine, and must never touch a target the operator is not
authorized to test.

## Decision
Add `cloudnova.range.webassess`, an **authorized, non-destructive** web posture
scanner, built on the same two invariants as the rest of the codebase:

1. **Authorization is the only gate, checked first.** Every networked function
   (`probe.fetch`, `probe.find_exposed_paths`) calls the Range scope engine
   before it opens a socket and refuses (`NotAuthorizedError`) on deny. The
   orchestrator (`runner.assess`) authorizes before anything else and returns an
   unauthorized result without ever reaching the network for out-of-scope targets.
2. **Fetch is isolated from analysis.** `probe` is the only module that does I/O;
   `checks` is pure functions over an `HttpSnapshot`, so the whole ruleset is
   deterministic and testable offline.

The assessment is deliberately **passive**: read-only GET/HEAD requests, a small
fixed list of well-known sensitive paths, an honest User-Agent, and a short
timeout. It reports missing security headers, weak cookie flags, permissive CORS,
plaintext transport, version disclosure, and reachable sensitive paths.

## Scope
The assessment is passive: read-only requests and a small fixed sensitive-path
check. Deeper, active techniques are covered separately (ADR 0014) and by the
mentor curriculum, always behind the scope gate ([ADR 0011](0011-range-authorization-first.md)).

## Consequences
- Findings reuse the shared `Severity`/`Confidence` vocabulary, so web findings
  read like every other CloudNova finding.
- New surface: `cloudnova range webassess <url> -s scope.yaml`.
- Adding a check is a pure function in `checks.py` plus a test, no I/O touched.
