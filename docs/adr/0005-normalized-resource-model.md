# 0005 — One normalized resource model across IaC formats

**Status:** Accepted

## Context
Terraform, CloudFormation, and Kubernetes describe the same cloud objects in
three dialects. Writing three parallel rule sets would triple the maintenance
and let the definition of "public bucket" drift between them.

## Decision
Every IaC parser normalizes its input into `CloudResource` (format, native
`type`, `name`, `config` dict, provenance). Checks reason over resources. We keep
the *dialect-native* type string (`aws_s3_bucket` vs `AWS::S3::Bucket`) rather
than inventing a lossy common type, because rules are written against a
provider's real vocabulary — it's the resource *shape* that needs unifying, not
the names.

## Consequences
- **+** Shared AWS primitives (public-ACL sets, world CIDRs, IAM-statement
  iteration) live in `checks/_aws.py` and are used by every format's pack.
- **+** `CloudResource` is the exact node type the Phase 3 attack-path graph will
  build on — parsing already produces the graph's vertices.
- **−** Per-format checks still exist where vocabulary differs (S3 in TF vs CFN).
  Accepted: shared *logic*, format-specific *field access*.
