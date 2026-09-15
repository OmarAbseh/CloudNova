# CloudNova Roadmap

A phased path from a clean engine to a full cloud + offensive security platform.
Each phase is independently useful and demo-able.

## Phase 0 — Foundation ✅ (this milestone)
Typed `Finding` model, plugin check engine, robust loader, CLI with CI gating,
console/JSON reporters, full test + lint + type gate, CI on 3.11/3.12.
Corrected every prototype detector (real CloudTrail schema, ACL-based S3, IP
aggregation) and killed the crash-on-malformed-input bugs.

## Phase 1 — Real IaC scanning
- Terraform HCL, CloudFormation, and Kubernetes manifest parsers → `Artifact`s.
- A real rule pack (dozens of checks) mapped to CIS Benchmarks.
- SARIF output for GitHub code-scanning integration.
- Baseline / suppression file so teams can accept known findings.

## Phase 2 — Live cloud posture
- Read-only AWS scanning via boto3 (S3, IAM, SG, RDS, CloudTrail config).
- Pluggable providers so Azure/GCP slot in behind the same `Artifact` seam.
- Credentials via the SDK's own provider chain (SSO / assumed role) — never
  pasted secrets.

## Phase 3 — Attack-path graph
- Model findings + resources as a graph; chain them into paths
  ("public EC2 → over-privileged role → readable S3 with PII").
- Rank by exploitability, not just per-finding severity. This is the
  senior-level differentiator over a flat checklist scanner.

## Phase 4 — Offensive / pentest modules (authorized-only)
- Safe, opt-in recon and exploit-*validation* (confirm a finding is real, don't
  weaponize it).
- Hard guardrails: explicit target authorization, scope allowlist, rate limits,
  full audit log, dry-run default. Refuses to run without written scope.
- This is what makes CloudNova a portfolio piece a security team recognizes.

## Phase 5 — AI agents
- Claude-powered triage: explain a finding, propose a fix PR, cluster related
  findings, draft the remediation runbook.
- An agent that reasons over the attack graph like a pentester and narrates the
  path. The `Finding` JSON schema (Phase 0) is already the agent's input format.

## Phase 6 — SaaS
- FastAPI service, multi-tenant, scan history + trend dashboards, scheduled
  scans, Slack/Jira integration. Only after the engine has proven itself.

---

### Guiding principles
1. **Honest output** — severity ⊥ confidence; never a guess dressed as a fact.
2. **The engine stays dumb** — all security knowledge lives in checks.
3. **Everything offensive is authorized, logged, and reversible.**
4. **Every decision gets an ADR.**
