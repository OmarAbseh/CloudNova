# 0007 — Attack paths via a resource graph, not more rules

**Status:** Accepted

## Context
A checklist scanner reports "bucket public" and "role over-privileged" as two
independent findings. The real risk is the *chain*: an internet-exposed instance
that can assume an admin role. More single-resource rules never surface that;
it's the relationships between resources that matter.

## Decision
Build a small directed graph (`ResourceGraph`, no networkx) where nodes are
`CloudResource`s tagged with security roles (internet-exposed, privileged,
data-store) and edges are relationships extracted from Terraform references
(`${aws_iam_role.r.name}` → a CAN_ASSUME/GRANTS/PROTECTED_BY edge). A bounded DFS
from each exposed node to a privileged/data target yields narrated attack paths,
emitted as CRITICAL findings through the normal reporting flow.

## Consequences
- **+** The differentiator: output a human explains in one sentence — "exposed
  EC2 → admin role" — that no per-rule check produces.
- **+** Reuses the normalized `CloudResource` (ADR 0005) as graph vertices and
  the `Finding` contract (ADR 0001) as output; nothing new leaks into the engine.
- **+** Confidence is MEDIUM: static references model *possible* reachability,
  not proven exploitability — honest about what we do and don't know.
- **−** Terraform-only for now (its references are explicit). CloudFormation
  (`Ref`/`GetAtt`) and live-cloud edges are future work. Data-exfil paths need an
  explicit reference today; IAM-implied access isn't yet edge-modeled.
- **−** DFS is bounded by depth and visited-set to stay fast and cycle-safe.
