# ADR 0016 — Tool orchestration, and where it stops

## Status
Accepted.

## Context
A credible pentest platform runs the industry-standard tools, not reimplementations.
Testers expect nmap, nuclei, ffuf and friends. CloudNova should drive them and
normalize their output into its own Finding contract.

## Decision
Add `cloudnova.range.toolkit`: thin adapters that shell out to a real tool and
parse its output into `Finding`s. Every adapter uses one shared flow (`execute`):

1. Authorize the target through the scope engine **before** running anything;
   out-of-scope targets never spawn a process.
2. Build a **list argv** (never a shell string) and run it with a timeout.
3. Parse stdout into Findings with a pure function (tested offline via an injected
   runner that returns canned tool output).

Adapters shipped: **nmap** (service discovery), **nuclei** (template checks),
**ffuf** (content discovery) — all recon/detection.

## Where it stops (deliberate)
The framework defines an `AGGRESSIVE` tier and gates it behind explicit
confirmation, but CloudNova does **not** ship autonomous credential-attack or
exploitation adapters (e.g. brute force, exploit execution, C2). Those are the
actual misuse vectors: a self-attested checkbox cannot verify authorization, and
an unattended attack tool is what turns a security product into an abuse tool.

That capability stays **operator-run, outside this package**: the operator runs
those tools by hand on their own toolkit box, under their own authorization, and
can ingest the results into CloudNova (e.g. `range recon` already parses nmap XML;
tool output can be imported the same way). The mentor teaches the techniques; the
platform orchestrates safe scanning and organizes evidence — it does not pull the
trigger on attacks by itself.

## Consequences
- Real tool coverage with consistent, mapped findings.
- Adding an adapter = build_argv + parse + a test; the scope gate is shared.
- The line is explicit and documented, so contributors don't "helpfully" add an
  autonomous exploitation adapter later.
