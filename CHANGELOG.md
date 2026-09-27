# Changelog

All notable changes to CloudNova. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); the project predates semver
releases, so entries are grouped by development phase.

## [Unreleased]

### Mentor advisor (Claude-powered Q&A)
- `cloudnova.range.mentor.advisor`: ask the mentor free-form questions. When an
  Anthropic API key is set it answers via Claude (claude-opus-5, adaptive
  thinking) with a tutor system prompt that stays methodology-focused and
  authorized-targets-only; with no key it falls back to a genuinely useful
  curriculum-based answer. CLI: `cloudnova range mentor ask "..."`. Optional
  `cloudnova[agent]` extra installs the anthropic SDK.

### Recon organizer
- `cloudnova.range.recon`: ingests operator-run `nmap -oX` output, gates every
  discovered host through the scope engine, and structures open services into an
  inventory with methodology next-steps per service. Out-of-scope hosts are
  flagged and their services are never surfaced. CLI: `cloudnova range recon`.

### Pentest report generation
- `cloudnova.range.report`: turns an engagement (metadata + findings, as a YAML
  file) into a professional Markdown pentest report — executive summary,
  findings-at-a-glance table, methodology, per-finding detail (severity/CVSS,
  impact, reproduction, remediation), appendix. Can adapt CloudNova scan findings.
- CLI: `cloudnova range report <engagement.yaml> [-o report.md]`.

### CloudNova Mentor (pentest tutor)
- New `cloudnova.range.mentor`: a prereq-linked curriculum (foundations → web/Burp
  → privesc → AD → cloud → reporting) mapped to tools, legitimate practice
  platforms, and certs; a coach that builds ordered learning paths, cert prep
  tracks (eJPT/PNPT/OSCP/CEH/eWPT), and job-readiness maps; and scope-gated guided
  lab sessions.
- CLI: `cloudnova range mentor path|topic|cert|jobs|lab`.

### CloudNova Range (authorized testing)
- New `cloudnova.range` module, authorization-first. Scope engine is a
  deny-by-default gate: a target is authorized only on an explicit in-scope
  match, exclusions always win, and a scope file must carry an authorization
  attestation or the engine authorizes nothing (fails closed). Supports IPs,
  CIDRs, exact/wildcard domains, and account IDs.
- CLI: `cloudnova range scope <file>` and `cloudnova range check <target> --scope`.

### IAM authoring & analysis
- `cloudnova iam generate`: authors a least-privilege IAM policy from a
  high-level grant spec (service + access + resource ARNs); refuses wildcard
  resources.
- `cloudnova iam analyze`: audits a policy for full/service wildcards,
  privilege-escalation actions and combos, wildcard principals, and NotAction+
  Allow. The generator's output analyzes clean (round-trip tested).

### Secret scanning
- Universal `SECRET_HARDCODED` check runs on every scanned file's raw text
  (AWS keys, PEM private keys, GitHub/Slack/Google tokens, generic key
  assignments). Evidence is redacted so the report never re-leaks the secret.
  Enabled by a new universal-check target ("*") in the engine.

### Reporting
- Self-contained HTML report (`scan --format html`): posture grade, severity
  summary, and every finding in one offline file with no external resources.
  All finding content is HTML-escaped.

### Scoring
- Transparent 0-100 / A-F security-posture score (`cloudnova.scoring`) replacing
  the thesis's black-box "AI risk score". Weighted by finding severity plus an
  attack-path penalty, with a full auditable breakdown; shown in console + JSON.

### Phase 5 — AI agents (started)
- MCP server (`cloudnova-mcp`) exposing `scan`, `list_checks`, and `attack_paths`
  so Claude or any MCP client can drive CloudNova. Logic lives in a new
  plain-dict `cloudnova.service` API; `mcp` is an optional extra.

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
