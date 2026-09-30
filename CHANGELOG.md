# Changelog

All notable changes to CloudNova. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); the project predates semver
releases, so entries are grouped by development phase.

## [Unreleased]

### Live cloud scanning (AWS + Azure)
- `cloudnova cloud aws` and `cloudnova cloud azure`: scan a LIVE account read-only
  with your own credentials and audit the actual resources — public S3 buckets /
  storage accounts, IAM users without MFA, stale access keys, security groups /
  NSGs open to the world on sensitive ports, public/unencrypted RDS and SQL. Same
  validated Finding contract (CIS + MITRE mappings) as the IaC scanner. Read-only
  (Describe/Get/List) only. Collectors are isolated + lazy-imported (`[aws]` /
  `[azure]` extras); the checks are pure and fully tested offline.
  ([ADR 0015](docs/adr/0015-live-cloud-scanning.md))

### Blackbox pentest checklist + active detection (Range)
- `cloudnova range checklist <url>`: runs the full PTES + OWASP WSTG blackbox
  methodology against an authorized target. Passive items resolve automatically;
  `--active` opts in to non-destructive intrusive *detection* (reflected XSS, SQL
  errors, path traversal); manual items are tracked with methodology. Either pass
  `--scope FILE` or self-attest with `--i-am-authorized "<name>"` (recorded in the
  report as operator responsibility). `-o report.md` writes an engagement report
  in the DarkShield layout with a vulnerability summary table.
- New `cloudnova.range.webassess.active`: opt-in active detection primitives, pure
  signature logic separated from networked probing, all scope-gated. No
  weaponization — detection only. ([ADR 0014](docs/adr/0014-active-detection.md))

### Authorized web assessment (Range)
- `cloudnova range webassess <url> -s scope.yaml`: a passive, non-destructive web
  posture scan that authorizes the target through the scope engine *before* any
  request, then reports missing security headers, weak cookie flags, permissive
  CORS, plaintext transport, version disclosure, and reachable sensitive paths.
  Read-only GET/HEAD only — no payloads, credential guessing, brute forcing, or
  exploitation. Fetch (`probe`) is isolated from pure analysis (`checks`), so the
  ruleset is fully testable offline. ([ADR 0013](docs/adr/0013-authorized-web-assessment.md))

### Mentor progress tracking
- The Mentor now remembers where you are: `cloudnova range mentor done <module>`
  marks a curriculum module complete, `progress` shows your completion bar, and
  `next` suggests the next modules whose prerequisites you've already finished.
  State persists in the config dir (`CLOUDNOVA_CONFIG_DIR` or `~/.cloudnova`),
  turning the static curriculum into a companion that walks with you.

### Triage in the dashboard
- The web scan-results page now has a per-finding **Explain** expander (what it is,
  why it matters, how to fix) rendered instantly offline — `explain_finding` gained
  an `allow_claude=False` mode so page rendering never makes API calls.

### Scan diff (posture over time)
- `cloudnova diff <old.json> <path>`: compares a saved scan against a fresh one and
  shows newly introduced vs fixed findings and the posture-score delta, matching by
  the baseline's stable fingerprint. `--fail-on-new` exits non-zero when a PR
  introduces any finding. `cloudnova.diff` is the reusable API.

### More checks (25 -> 30)
- Terraform: KMS key rotation disabled (`TF_KMS_NO_ROTATION`), EC2 IMDSv2 not
  enforced (`TF_EC2_IMDSV2`).
- CloudFormation: KMS key rotation disabled (`CFN_KMS_NO_ROTATION`).
- Kubernetes: dangerous Linux capabilities (`K8S_DANGEROUS_CAPABILITIES`),
  writable root filesystem (`K8S_WRITABLE_ROOT_FS`).

### AI finding triage
- `cloudnova triage <path>`: scans, then explains the worst findings in plain
  English — what it is, why it matters (attacker's view + friendly ATT&CK names),
  and a concrete fix. Uses Claude when ANTHROPIC_API_KEY is set, with a useful
  templated offline fallback. `cloudnova.triage.explain_finding` is the reusable API.

### Web dashboard redesign
- Professional dark UI with a red-accented palette (not the default warm tones), a
  Three.js 3D animated hero (wireframe icosahedron) with a CSS orb fallback,
  gradient buttons, capability cards, and a responsive layout. All content stays
  HTML-escaped and server-rendered; the 3D is progressive enhancement.

### Web dashboard (the website)
- `cloudnova.web`: a local FastAPI dashboard (optional `web` extra, `cloudnova-web`).
  Run a scan from the browser and view findings, the posture grade, and attack
  paths; browse the pentest-mentor learning path. Server-rendered, HTML-escaped,
  binds to 127.0.0.1, reuses the tested service/engine — exposes only the
  defensive scanner and mentor over HTTP, never Range's target-facing commands.

### Range personas
- `cloudnova.range.persona`: switchable operator identity — `cloudnova` (the
  professional product face) and `gh0st` (personal handle). Cosmetic only: it
  changes greetings and the default report byline, never any security behavior.
  Selection via `CLOUDNOVA_PERSONA` env var or a saved config. CLI:
  `cloudnova range whoami`, `range persona list`, `range persona use <id>`.

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
