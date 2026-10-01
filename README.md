# 🛡️ CloudNova

**Find cloud misconfigurations before attackers do, then learn to think like one.**

CloudNova is a cloud security platform in two halves that share one engine:

- **Scanner**, point it at Terraform, CloudFormation, Kubernetes manifests,
  CloudTrail logs, or auth/config logs and it reports misconfigurations as
  structured, actionable findings, mapped to CIS Benchmarks and MITRE ATT&CK,
  emittable as SARIF, and gate-able in CI.
- **Range**, an *authorization-first* offensive-security side whose headline
  feature is a **pentest mentor**: a structured curriculum that takes you from
  foundations to job- and cert-ready, with progress tracking and scope-gated
  practice labs.

[![CI](https://github.com/OmarAbseh/CloudNova/actions/workflows/ci.yml/badge.svg)](https://github.com/OmarAbseh/CloudNova/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)

> **New here?** Read [GETTING_STARTED.md](./GETTING_STARTED.md), a plain-language
> walkthrough of every feature.

---

## Why CloudNova is different

Most scanners hand you a flat checklist. CloudNova adds the two things a
checklist misses:

1. **Attack paths.** It builds a graph of your resources and reports exploitable
   *chains*, "an internet-exposed instance can assume a role that reaches admin"
   - as one narrated CRITICAL finding, not scattered nits.
2. **A path for the human.** The Range mentor turns the same security knowledge
   into a curriculum, so the person running the tool actually levels up.

Every finding carries a **severity** *and* an independent **confidence**, maps to
CIS + MITRE ATT&CK, and rolls up into a **transparent posture score** (0-100 /
A-F) with a full breakdown, no black box.

---

## Quick start

```bash
pip install -e ".[dev]"                          # install with dev tooling

cloudnova scan examples                          # scan the bundled fixtures
cloudnova scan . --format json                   # machine-readable output
cloudnova scan . --format sarif                  # SARIF 2.1.0 for GitHub code-scanning
cloudnova scan . --format html > report.html     # shareable HTML report
cloudnova scan . --fail-on high                  # non-zero exit for CI gating
cloudnova checks                                 # list the loaded ruleset (30 checks)

cloudnova baseline .                             # accept current findings as a baseline
cloudnova scan . --baseline .cloudnova-baseline.json   # report only NEW findings
cloudnova diff old-scan.json .                   # posture drift vs a saved scan
```

### Web dashboard

A local browser dashboard (optional `web` extra), run a scan and see findings,
the posture grade, and attack paths, plus the pentest mentor with a live
progress tracker:

```bash
pip install -e ".[web]"
cloudnova-web            # serves http://127.0.0.1:8000 (local operator tool)
```

Example CLI output:

```
CRITICAL  CT_IAM_WILDCARD_ADMIN   AdminRole      IAM policy grants wildcard privileges
HIGH      CT_S3_PUBLIC_ACL        company-data   S3 object written with a public ACL
HIGH      IAC_ACCESS_PUBLIC       access_control.public   Resource exposes public access
HIGH      LOG_SSH_BRUTE_FORCE     10.0.0.5       120 failed SSH attempts from one IP
```

---

## What it detects today

**30 checks across 5 input formats**, Terraform, CloudFormation, Kubernetes,
CloudTrail logs, and generic config/auth logs. Run `cloudnova checks` for the
live list. Highlights:

| Area | Formats | Examples |
|---|---|---|
| **S3 exposure** | Terraform, CloudFormation, CloudTrail | Public ACLs (by ACL, never by name), missing encryption |
| **Network** | Terraform, CloudFormation | Security groups open to `0.0.0.0/0`, severity escalated for SSH/RDP/DB ports |
| **IAM** | Terraform, CloudFormation, CloudTrail | Wildcard `Action`/`Resource`, real policy parsing (incl. `jsonencode`) |
| **Encryption / keys** | Terraform, CloudFormation | KMS key rotation disabled, unencrypted resources |
| **Compute** | Terraform | EC2 IMDSv2 not enforced |
| **Kubernetes** | K8s manifests | Privileged containers, host namespaces, run-as-root, dangerous capabilities, writable root FS |
| **Runtime logs** | auth log | SSH brute force **aggregated per source IP**, severity by volume |
| **Secrets** | any | Hard-coded credentials and keys |

### Live cloud scanning (AWS + Azure)

Beyond config files, CloudNova can log in to a **live account** (read-only, your
own credentials) and audit the actual resources:

```bash
pip install -e ".[aws]"     # or ".[azure]" / ".[gcp]"
cloudnova cloud aws --profile prod --region eu-west-1
cloudnova cloud azure --subscription <id>
cloudnova cloud gcp --project <id>
```

Public buckets/storage, IAM users without MFA, stale keys, security groups/NSGs
open to the world, public/unencrypted databases, as the same findings, mapped to
CIS + MITRE. Read-only only; nothing is created or changed.
([ADR 0015](docs/adr/0015-live-cloud-scanning.md))

### Attack paths (the differentiator)

```
CRITICAL  GRAPH_ATTACK_PATH   aws_instance.web
  An attacker who compromises the internet-exposed resource 'aws_instance.web'
  reaches a privileged identity (privilege escalation to admin).
  Chain: aws_instance.web - can assume → aws_iam_instance_profile.app
         - can assume → aws_iam_role.app
```

Runs automatically during `scan` (disable with `--no-graph`).
([ADR 0007](docs/adr/0007-attack-path-graph.md))

### Author & audit IAM

```bash
cloudnova iam generate grants.yaml -o policy.json   # least-privilege policy from intents
cloudnova iam analyze policy.json                   # audit for escalation vectors
```

`generate` refuses wildcard resources (least-privilege by construction);
`analyze` flags full/service wildcards, privilege-escalation actions and combos
(`iam:PassRole` + `ec2:RunInstances`), wildcard principals, and `NotAction`+Allow.
([ADR 0010](docs/adr/0010-iam-generate-and-analyze.md))

### CloudNova Range, authorized testing, authorization-first

`cloudnova.range` is the offensive / validation side, built so the **scope engine
is the only entry point**. It decides whether a target is authorized *before*
anything can act on it, deny-by-default, exclusions win, and it refuses
everything unless a scope file carries an authorization attestation.

```bash
cloudnova range scope scope.yaml                          # show authorized scope + attestation
cloudnova range check api.example.com -s scope.yaml       # ALLOW/DENY (exit 0/1)
```

Every target-facing action passes the scope engine first.
([ADR 0011](docs/adr/0011-range-authorization-first.md))

**Authorized web assessment** (`cloudnova range webassess`): a passive,
non-destructive posture scan of an in-scope web target, missing security
headers, weak cookies, permissive CORS, plaintext transport, version disclosure,
and reachable sensitive paths. It authorizes the target *before* any request and
uses read-only GET/HEAD requests.

```bash
cloudnova range webassess https://app.example.com -s scope.yaml
```

([ADR 0013](docs/adr/0013-authorized-web-assessment.md))

**Mentor, your pentest tutor** (`cloudnova range mentor`): a structured
curriculum from foundations to job- and cert-ready, grounded in real cert
domains (eJPT / PNPT / OSCP / CEH) and pentest job requirements, now with
progress tracking that walks with you.

```bash
cloudnova range mentor path                 # ordered learning path (prereqs first)
cloudnova range mentor topic burp-suite     # concepts, tools, practice resources, certs
cloudnova range mentor cert OSCP            # a certification prep track
cloudnova range mentor jobs junior          # skills a hiring level expects
cloudnova range mentor done foundations     # mark a module complete
cloudnova range mentor progress             # your completion bar + what's next
cloudnova range mentor lab box.example.com -s scope.yaml   # guided lab (scope-gated)
```

([ADR 0012](docs/adr/0012-mentor-tutor.md))

### Use it from an AI agent (MCP)

CloudNova ships a [Model Context Protocol](https://modelcontextprotocol.io)
server so any MCP-capable AI client can scan and reason about your infrastructure:

```bash
pip install -e ".[mcp]"
cloudnova-mcp            # serves tools: scan, list_checks, attack_paths
```

Optional AI triage (`cloudnova triage`) and mentor Q&A explain findings in plain
English via the Anthropic API when `ANTHROPIC_API_KEY` is set, with a useful
offline fallback when it isn't. ([ADR 0008](docs/adr/0008-mcp-server.md))

---

## Architecture

```
files ──► loader ──► Artifact(kind, data) ──► Engine ──► [ matching Checks ] ──► [ Finding ] ──► reporters
          (I/O)       (typed, parsed)          (isolates                          (one typed        (console
                                                errors)                            contract)          /json/sarif/html)
```

- **`Finding`**, one immutable, validated Pydantic model is the contract every
  check produces and every formatter consumes. ([ADR 0001](docs/adr/0001-finding-as-the-core-contract.md))
- **Checks are plugins**, subclass `Check`, add `@register`; the engine
  discovers them. ([ADR 0002](docs/adr/0002-plugin-check-registry.md))
- **Parse ≠ check**, only the loader touches disk; checks are pure functions of
  parsed data, so one bad file can't crash a scan. ([ADR 0003](docs/adr/0003-parse-then-check-separation.md))
- **Severity ⊥ confidence**, how bad *and* how sure. ([ADR 0004](docs/adr/0004-severity-and-confidence-are-separate.md))
- **One normalized resource model**, TF/CFN/K8s parse into the same
  `CloudResource`, so AWS rules are shared, not triplicated. ([ADR 0005](docs/adr/0005-normalized-resource-model.md))
- **Baselines by fingerprint**, gate only on *new* findings, stable across
  reformatting. ([ADR 0006](docs/adr/0006-baseline-fingerprints.md))

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

CI runs the same gate on Python 3.11 and 3.12, plus a secret-scanning hook.
See [DEVELOPMENT.md](./DEVELOPMENT.md) for the module map and invariants.

---

## Roadmap

See [ROADMAP.md](./ROADMAP.md). In short: IaC scanning → live cloud scanning
(AWS/Azure/GCP) → attack-path graph → authorized offensive modules → AI triage
→ hosted SaaS.

## License

MIT, see [LICENSE](./LICENSE).

---

<sub>A **Floatly IT Solutions** project.</sub>
