# 🛡️ CloudNova

**A cloud security scanning engine.** Point it at IaC configs, CloudTrail logs,
or auth logs and it reports misconfigurations as structured, actionable findings
— mapped to CIS Benchmarks and MITRE ATT&CK, and gate-able in CI.

> Started as a University of Debrecen thesis; being rebuilt as a real
> production-grade security tool. The original prototype is preserved under
> [`legacy/`](./legacy).

[![CI](https://github.com/OmarAbseh/CloudNova/actions/workflows/ci.yml/badge.svg)](https://github.com/OmarAbseh/CloudNova/actions)

---

## Quick start

```bash
pip install -e ".[dev]"        # install with dev tooling

cloudnova scan examples        # scan the bundled example fixtures
cloudnova scan . --format json # machine-readable output
cloudnova scan . --fail-on high  # non-zero exit for CI gating
cloudnova checks               # list the loaded ruleset
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

| Check ID | Target | Severity | Detects |
|---|---|---|---|
| `CT_IAM_WILDCARD_ADMIN` | CloudTrail | Critical | `Action:"*"` on `Resource:"*"` in a real IAM policy document |
| `CT_S3_PUBLIC_ACL` | CloudTrail | High | Objects written with a public **canned ACL** (not a name guess) |
| `IAC_ACCESS_PUBLIC` | YAML config | High | `access_control.public: true` |
| `IAC_AUTH_NO_PASSWORD` | YAML config | Medium | `authentication.password_required: false` |
| `IAC_SESSION_NO_TIMEOUT` | YAML config | Low | Disabled / missing session timeout |
| `LOG_SSH_BRUTE_FORCE` | auth log | Med/High | Failed SSH logins **aggregated per source IP** |

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
