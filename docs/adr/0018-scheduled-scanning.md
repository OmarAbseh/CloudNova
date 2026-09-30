# ADR 0018 — Scheduled scanning via history + drift (not a daemon)

## Status
Accepted.

## Context
Customers want continuous monitoring: "tell me when something new breaks." The
naive approach is to build a scheduler daemon inside CloudNova. That's the wrong
call — cron, systemd timers, and CI schedulers already do scheduling reliably.

## Decision
Add `cloudnova.monitor`: make scans *stateful over time* and let the platform's
scheduler run them.

- `record_scan` stores a timestamped JSON snapshot per target (isolated storage
  under a data dir; the only disk-touching module for this feature).
- `diff_against_latest` compares a fresh scan to the previous snapshot using the
  existing `diff` engine, returning introduced / fixed / unchanged + score delta.
- `trend` returns the posture time series across snapshots.
- CLI: `cloudnova monitor <path> [--fail-on-new]` (scan, diff, record; non-zero
  exit on new findings for alerting) and `cloudnova history <path>`.

Scheduling is delegated: run `monitor` from cron, a systemd timer, or a scheduled
GitHub Action. `--fail-on-new` turns any of those into an alert.

## Consequences
- Continuous monitoring with zero bespoke scheduler code.
- Snapshots are the substrate for the Phase 2 web trend dashboard.
- Next: notification channels (Slack/email) on drift, wired to the same signal.
