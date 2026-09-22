# Changelog

All notable changes to CloudNova. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); the project predates semver
releases, so entries are grouped by development phase.

## [Unreleased]

### Phase 3 — Attack-path graph
- `cloudnova.graph`: a dependency-free resource graph. Nodes are normalized
  `CloudResource`s tagged with security roles (internet-exposed, privileged,
  data-store, compute); edges are relationships extracted from Terraform
  references (`PROTECTED_BY` / `CAN_ASSUME` / `GRANTS`).
- Bounded, cycle-safe DFS reports exploitable chains as narrated CRITICAL
  findings ("internet-exposed EC2 — can assume → admin role"). Runs during
  `scan` (`--no-graph` to disable).

### Phase 1 — IaC scanning
- Terraform (HCL, incl. `jsonencode` policy resolution), CloudFormation
  (JSON/YAML with intrinsic tags), and multi-document Kubernetes parsers, all
  normalized to `CloudResource`.
- 24 checks across 5 formats mapped to CIS Benchmarks + MITRE ATT&CK.
- SARIF 2.1.0 output and a GitHub code-scanning workflow.
- Baseline/suppression by content fingerprint (`cloudnova baseline`).
- `--min-severity` filter and `--fail-on` CI gate.

### Phase 0 — Foundation
- Rebuilt from the thesis prototype into a typed, tested package.
- Immutable Pydantic `Finding` contract; plugin check registry; loader/check
  separation so malformed input is recorded, never fatal.
- Typer CLI (`scan`, `checks`, `baseline`); console + JSON reporters.
- Full quality gate: ruff, mypy (strict), pytest; CI on Python 3.11 & 3.12.
- Security hygiene: `.gitignore`, `.env.example`, detect-private-key pre-commit
  hook (the prototype had leaked a live key — since revoked).
- Original prototype preserved under `legacy/`.
