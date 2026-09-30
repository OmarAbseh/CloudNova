# CloudNova Roadmap

A phased path from a clean engine to a full cloud + offensive security platform.
Each phase is independently useful and demo-able.

## Phase 0 — Foundation ✅ (this milestone)
Typed `Finding` model, plugin check engine, robust loader, CLI with CI gating,
console/JSON reporters, full test + lint + type gate, CI on 3.11/3.12.
Corrected every prototype detector (real CloudTrail schema, ACL-based S3, IP
aggregation) and killed the crash-on-malformed-input bugs.

## Phase 1 — Real IaC scanning ✅
- ✅ Terraform HCL, CloudFormation (JSON/YAML incl. intrinsic tags), and
  multi-document Kubernetes manifest parsers → normalized `CloudResource`s.
- ✅ Rule packs mapped to CIS Benchmarks + MITRE ATT&CK (24 checks, 5 formats).
- ✅ SARIF 2.1.0 output + GitHub code-scanning workflow.
- ✅ Baseline / suppression by content fingerprint (`cloudnova baseline`).
- ⏭️ Next: broaden the AWS rule packs (RDS, KMS, VPC flow logs, public AMIs).

## Phase 2 — Live cloud posture ✅
- ✅ Read-only AWS scanning via boto3 (S3, IAM, security groups, RDS).
- ✅ Read-only Azure scanning (storage, NSGs, SQL) behind the same check/collect seam.
- ✅ Credentials via each SDK's own provider chain (profile/role, DefaultAzureCredential)
  — never pasted secrets. Collectors are read-only and resilient to partial perms.
- ⏭️ Next: GCP, more services, feed live findings into the posture score + graph.

## Phase 3 — Attack-path graph 🚧
- ✅ Resource graph (`cloudnova.graph`): nodes tagged with security roles,
  edges extracted from Terraform references; bounded DFS finds exploitable chains.
- ✅ Attack paths surface as narrated CRITICAL findings in the normal scan output
  ("internet-exposed EC2 — can assume → admin role").
- ✅ CloudFormation edges too (Ref / Fn::GetAtt); attack paths across both IaC formats.
- ⏭️ Next: live-cloud edges, IAM-implied data-access edges, exploitability ranking.

## Phase 4 — Offensive / pentest modules (authorized-only) 🚧
- Safe, opt-in recon and exploit-*validation* (confirm a finding is real, don't
  weaponize it).
- Hard guardrails: explicit target authorization, scope allowlist, rate limits,
  full audit log, dry-run default. Refuses to run without written scope.
- This is what makes CloudNova a portfolio piece a security team recognizes.
- ✅ `cloudnova.range` scope/authorization engine: deny-by-default gate, exclusions
  win, attestation required (fails closed). Every capability gates through it.
- ✅ Mentor: scope-aware pentest tutor (curriculum, cert tracks, guided labs).
- ✅ Report generator: engagement notes -> professional Markdown report.
- ✅ Authorized web assessment (`range webassess`): passive posture scan, scope-gated.
- ✅ Blackbox checklist (`range checklist`): PTES + OWASP WSTG, passive + opt-in active
  detection, DarkShield-style report; self-authorization ("no scope" responsibility tick).
- ✅ Tool orchestration (`range tool nmap|nuclei|ffuf`): drive real tools, scope-gated,
  output normalized to Findings. (Autonomous exploitation/credential attacks are
  deliberately out of scope — operator-run only. See ADR 0016.)
- ⏭️ Next: ingest operator tool output (hydra/sqlmap results) into reports.

## Phase 5 — AI agents 🚧
- ✅ MCP server (`cloudnova-mcp`): exposes scan / list_checks / attack_paths so
  Claude or any MCP client can drive CloudNova; logic in the tested
  `cloudnova.service` API.
- ✅ Mentor advisor: Claude-powered Q&A (`range mentor ask`) with an offline
  curriculum fallback and a tutor/guardrail system prompt.
- ✅ Claude-powered finding triage (`cloudnova triage`): plain-English explanation,
  attacker view, and concrete fix per finding, with an offline fallback.
- ⏭️ Next: propose-a-fix PRs, attack-graph narration.

## Phase 6 — SaaS / Web 🚧
- ✅ Local FastAPI dashboard (`cloudnova-web`): run scans and view findings, the
  posture grade, and attack paths in the browser; browse the mentor path.
- ✅ Dashboard auth (HTTP Basic) + security headers; `$PORT` support; refuses to bind
  a public interface without a password. `render.yaml` / `Procfile` / `DEPLOY.md`.
- ✅ Marketing landing page (`site/`) for Vercel; GitHub Action for CI scanning.
- ⏭️ Next: see Phase 7.

## Phase 7 — Growth & scale (next build phase) 🔜
The high-value features that turn the platform into a sellable SaaS. Tackled after
the current phase lands, then we look for more.
- **Multi-tenant auth + RBAC** (Supabase): per-user accounts, org/teams, isolation —
  the prerequisite for exposing cloud + pentest features in the web UI safely.
- **Scan history + trend dashboards**: posture over time, per-target.
- **Scheduled / continuous scanning** with drift alerts.
- **Integrations**: Slack + email alerts, Jira/Linear ticket creation, GitHub PR checks.
- **PDF/branded report export** (the DarkShield engagement layout as a real document).
- **GCP scanning**; broaden AWS/Azure service coverage.
- **Compliance dashboards**: PCI DSS 4.0.1, SOC 2, NIS2, CIS mappings + evidence.
- **Operator tool-output ingestion**: import hydra/sqlmap/nuclei results into reports.
- **Billing**: Stripe + the tier plan (Community / Starter / Pro / Team).

---

### Guiding principles
1. **Honest output** — severity ⊥ confidence; never a guess dressed as a fact.
2. **The engine stays dumb** — all security knowledge lives in checks.
3. **Everything offensive is authorized, logged, and reversible.**
4. **Every decision gets an ADR.**
