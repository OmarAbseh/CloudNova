# 0006 — Baselines use content fingerprints, not line numbers

**Status:** Accepted

## Context
Teams adopting a scanner have a backlog they can't fix at once; CI should fail
only on *new* findings. A baseline must survive code reformatting and tool
upgrades, or it becomes noise the first time someone edits a file.

## Decision
Each finding gets a fingerprint hashed from stable identity — `check_id`, file
path, resource address, and evidence — deliberately excluding line numbers,
timestamps, and free-text descriptions. The baseline is a JSON set of these
fingerprints; `scan --baseline` subtracts them.

## Consequences
- **+** Reformatting a file (line shifts) doesn't invalidate the baseline.
- **+** The baseline file is compact and reveals no source content.
- **−** Two truly-identical findings on the same resource+evidence collapse to
  one fingerprint. Acceptable: they are the same issue for triage purposes.
