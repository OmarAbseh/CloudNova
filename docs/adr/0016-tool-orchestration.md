# ADR 0016, Tool orchestration

## Status
Accepted.

## Context
A credible pentest platform runs the industry-standard tools, not reimplementations.
Testers expect nmap, nuclei, ffuf and friends. CloudNova should drive them and
normalize their output into its own Finding contract.

## Decision
Add `cloudnova.range.toolkit`: thin adapters that shell out to a real tool and parse
its output into `Finding`s. Every adapter uses one shared flow (`execute`):

1. Authorize the target through the scope engine before running anything; out-of-scope
   targets never spawn a process.
2. Build a list argv (never a shell string) and run it with a timeout.
3. Parse stdout into Findings with a pure function, tested offline via an injected
   runner that returns canned tool output.

Adapters shipped: **nmap** (service discovery), **nuclei** (template checks), **ffuf**
(content discovery). The framework defines PASSIVE / ACTIVE / AGGRESSIVE tiers;
aggressive tools require explicit operator confirmation before they run.

## Consequences
- Real tool coverage with consistent, mapped findings.
- Adding an adapter = build_argv + parse + a test; the scope gate and runner are shared.
- Operator-run tools can also be ingested after the fact, `range recon` already parses
  nmap XML, and other tool output can be imported the same way.
