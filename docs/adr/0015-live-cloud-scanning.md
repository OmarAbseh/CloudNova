# ADR 0015 - Live cloud scanning (AWS + Azure), read-only

## Status
Accepted.

## Context
Until now CloudNova scanned cloud *config* (Terraform/CFN/K8s) and *logs*
(CloudTrail). That misses drift and anything created outside IaC. A credible cloud
security product must also audit the *live* account.

## Decision
Add `cloudnova.cloud` with AWS and Azure scanners that follow the project's
parse/check split:

- A **collector** (`_aws_collect`, `_azure_collect`) makes read-only SDK calls
  (Describe/Get/List) and returns a plain inventory dataclass. It is lazy-imported
  so the vendor SDKs are optional extras (`[aws]`, `[azure]`), and each service is
  wrapped so partial credentials yield a partial inventory.
- Pure **check** functions turn the inventory into validated `Finding`s - no
  network, so they are fully unit-tested offline by feeding inventories directly.
- `scan_aws(inventory=...)` / `scan_azure(inventory=...)` accept an injected
  inventory, which is how the tests exercise the whole path without credentials.

Initial coverage: S3 public/unencrypted, IAM no-MFA + stale keys, security groups
open to the world, RDS public/unencrypted; Azure storage public-blob/HTTP/
unencrypted, NSGs open to the internet, SQL public network access.

## Constraints
Read-only only: the collectors never create, modify, or delete. Credentials come
from the operator's own environment (AWS profile/role, Azure DefaultAzureCredential)
- CloudNova stores nothing. This is a security audit of an account you control, not
an attack.

## Consequences
- Live findings share the severity/confidence/CIS/MITRE vocabulary and reporters
  with the rest of CloudNova.
- Adding a check is a pure function + a test; adding coverage for a new service is
  a collector method + inventory fields.
- Next: GCP, more services, and feeding live findings into the posture score and
  attack-path graph.
