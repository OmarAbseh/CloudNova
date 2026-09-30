# ADR 0017 — Compliance mapping (ISO 27001 / NIST CSF / PCI DSS)

## Status
Accepted.

## Context
Enterprise buyers don't ask "how many findings?" — they ask "are we ISO 27001 /
NIST / PCI compliant?" CloudNova needs to speak that language to sell into
mid-market and enterprise, and to feed the compliance dashboards on the roadmap.

## Decision
Add `cloudnova.compliance`: map findings onto framework controls and report
per-control status with an honest, coverage-based score.

- Findings are classified into security **categories** (exposure, encryption,
  identity, logging, secrets) by their check-id naming — so new checks are covered
  automatically, without editing a giant per-check table.
- Each category maps to the relevant controls in each framework
  (`CATEGORY_CONTROLS`), against curated human-readable control catalogs
  (`CATALOGS`).
- A control is **FAIL** if any finding maps to it, **PASS** if it is one CloudNova
  assesses and nothing failed it, **NOT_ASSESSED** if it is in the catalog but
  outside what we currently check.
- **Score = passed / (passed + failed)** — it never counts controls we don't test,
  so we never overstate compliance. Honesty over a vanity number.

CLI: `cloudnova compliance <path> --framework iso27001|nist|pci|all`.

## Consequences
- The same scan now produces both technical findings and a compliance view.
- Extending coverage = add controls to a catalog + wire the category. Adding a new
  framework = one catalog + one category map.
- Next (Phase 2): a web compliance dashboard, evidence export, and SOC 2 / CIS
  benchmark views built on this same engine.
