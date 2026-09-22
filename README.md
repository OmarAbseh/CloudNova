# 🛡️ CloudNova

**A cloud security scanning engine.** Point it at Terraform, CloudFormation,
Kubernetes manifests, CloudTrail logs, or config/auth logs and it reports
misconfigurations as structured, actionable findings — mapped to CIS Benchmarks
and MITRE ATT&CK, emittable as SARIF, and gate-able in CI.

> Started as a University of Debrecen thesis; being rebuilt as a real
> production-grade security tool. The original prototype is preserved under
> [`legacy/`](./legacy).

[![CI](https://github.com/OmarAbseh/CloudNova/actions/workflows/ci.yml/badge.svg)](https://github.com/OmarAbseh/CloudNova/actions)

---

## Quick start

```bash
pip install -e ".[dev]"        # install with dev tooling

cloudnova scan examples          # scan the bundled example fixtures
cloudnova scan . --format json   # machine-readable output
cloudnova scan . --format sarif  # SARIF 2.1.0 for GitHub code-scanning
cloudnova scan . --fail-on high  # non-zero exit for CI gating
cloudnova scan . --min-severity high  # only show high+ findings
cloudnova checks                 # list the loaded ruleset

cloudnova baseline .             # accept current findings as a baseline
cloudnova scan . --baseline .cloudnova-baseline.json  # report only NEW findings
```

Example output:

```
CRITICAL  CT_IAM_WILDCARD_ADMIN   AdminRole      IAM policy grants wildcard privileges
HIGH      CT_S3_PUBLIC_ACL        company-data   S3 object written with a public ACL
HIGH      IAC_ACCESS_PUBLIC       access_control.public   Resource exposes public access
HIGH      LOG_SSH_BRUTE_FORCE     10.0.0.5       120 failed SSH attempts from one IP
```

---

## What it detects today

**24 checks across 5 input formats** — Terraform, CloudFormation, Kubernetes,
CloudTrail logs, and generic config/auth logs. Run `cloudnova checks` for the
live list. Highlights:

| Area | Formats | Examples |
|---|---|---|
| **S3 exposure** | Terraform, CloudFormation, CloudTrail | Public ACLs (by ACL, never by name), missing encryption |
| **Network** | Terraform, CloudFormation | Security groups open to `0.0.0.0/0`, with severity escalated for SSH/RDP/DB ports |
| **IAM** | Terraform, CloudFormation, CloudTrail | Wildcard `Action`/`Resource`, parsing real policy documents (incl. `jsonencode`) |
| **Kubernetes** | K8s manifests | Privileged containers, host namespace sharing, run-as-root, privilege escalation |
| **Runtime logs** | auth log | SSH brute force **aggregated per source IP**, severity by volume |

Every finding maps to CIS Benchmark controls and MITRE ATT&CK techniques, and
carries a severity **and** an independent confidence.

Each scan also reports a **transparent posture score** (0-100, A-F) with a full
breakdown of how it was computed — no black box. ([ADR 0009](docs/adr/0009-transparent-posture-score.md))

### Attack paths (the differentiator)

Beyond per-resource findings, CloudNova builds a **graph** of your resources and
reports exploitable *chains* — the thing a checklist scanner misses:

```
CRITICAL  GRAPH_ATTACK_PATH   aws_instance.web
  An attacker who compromises the internet-exposed resource 'aws_instance.web'
  reaches a privileged identity (privilege escalation to admin).
  Chain: aws_instance.web — can assume → aws_iam_instance_profile.app
         — can assume → aws_iam_role.app
```

This runs automatically during `scan` (disable with `--no-graph`).

### Use it from an AI agent (MCP)

CloudNova ships a [Model Context Protocol](https://modelcontextprotocol.io)
server so Claude or any MCP client can scan and reason about your infrastructure:

```bash
pip install -e ".[mcp]"
cloudnova-mcp            # serves tools: scan, list_checks, attack_paths
```

An agent can then ask *"scan this repo, explain the worst attack path, and
propose the Terraform fix."* All server logic is a thin wrapper over the tested
`cloudnova.service` API. ([ADR 0008](docs/adr/0008-mcp-server.md))

---

## Architecture

```
files ──► loader ──► Artifact(kind, data) ──► Engine ──► [ matching Checks ] ──► [ Finding ] ──► reporters
          (I/O)       (typed, parsed)          (isolates                          (one typed        (console
                                                errors)                            contract)          / json)
```

- **`Finding`** — one immutable, validated Pydantic model is the contract every
  check produces and every formatter consumes. ([ADR 0001](docs/adr/0001-finding-as-the-core-contract.md))
- **Checks are plugins** — subclass `Check`, add `@register`; the engine
  discovers them. Adding a rule never touches the engine. ([ADR 0002](docs/adr/0002-plugin-check-registry.md))
- **Parse ≠ check** — only the loader touches disk; checks are pure functions of
  parsed data, so one bad file can't crash a scan. ([ADR 0003](docs/adr/0003-parse-then-check-separation.md))
- **Severity ⊥ confidence** — the scanner says how bad *and* how sure, so it
  doesn't cry wolf. ([ADR 0004](docs/adr/0004-severity-and-confidence-are-separate.md))
- **One normalized resource model** — Terraform, CloudFormation, and Kubernetes
  all parse into the same `CloudResource`, so AWS rules are shared, not
  triplicated. ([ADR 0005](docs/adr/0005-normalized-resource-model.md))
- **Baselines by fingerprint** — accept a backlog and gate only on *new*
  findings, stable across reformatting. ([ADR 0006](docs/adr/0006-baseline-fingerprints.md))
- **Attack-path graph** — resources become a graph; a walk from an
  internet-exposed node to an admin role or data store is reported as one
  narrated CRITICAL finding, not scattered nits. ([ADR 0007](docs/adr/0007-attack-path-graph.md))

Every design decision is written up in [`docs/adr/`](docs/adr).

---

## Development

```bash
pip install -e ".[dev]"
ruff check src tests      # lint
ruff format src tests     # format
mypy                      # strict type check
pytest --cov=cloudnova    # tests + coverage
pre-commit install        # run all of the above on every commit
```

CI runs the same gate on Python 3.11 and 3.12, plus a secret-scanning hook so a
credential can never be committed again.

### Adding a check

```python
from cloudnova.core.check import Check, register
from cloudnova.core.findings import Finding, Location, Severity

@register
class MyRule(Check):
    id = "IAC_MY_RULE"
    title = "..."
    severity = Severity.HIGH
    target = "iac_config"

    def run(self, artifact):
        if is_bad(artifact.data):
            yield Finding(check_id=self.id, title=self.title, severity=self.severity,
                          location=Location(path=artifact.path),
                          description="...", remediation="...")
```

Add its module to `src/cloudnova/checks/__init__.py`, write a test, done.

---

## Roadmap

See [ROADMAP.md](./ROADMAP.md). In short: real IaC (Terraform/CFN/K8s) →
live cloud scanning (AWS/Azure/GCP) → attack-path graph → authorized offensive
modules → AI triage agents → SaaS.

## License

MIT — see [LICENSE](./LICENSE).
