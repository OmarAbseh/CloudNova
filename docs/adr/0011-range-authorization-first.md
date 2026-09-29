# 0011 — CloudNova Range is authorization-first

**Status:** Accepted

## Context
The roadmap's offensive/validation phase (testing that a finding is really
exploitable, and — for users — probing their own authorized cloud accounts) is
the highest-risk part of the project. Built carelessly it becomes a weapon;
built correctly it's what a security team recognizes as professional.

## Decision
Introduce `cloudnova.range` and make **authorization the only entry point**. The
scope engine is a deny-by-default policy gate:

1. A target is authorized only if it explicitly matches an in-scope entry.
2. Out-of-scope exclusions always win over inclusions.
3. A scope file must carry an authorization attestation (program, authorized_by,
   acknowledged) or the engine authorizes nothing — it fails closed.

Every future Range capability (recon organization, finding validation, a
practice-lab tutor, authorized cloud probing) must obtain an ALLOW decision from
this engine before acting. The engine only decides; it never touches a target.

## Consequences
- **+** The offensive side is legitimate by construction: nothing can act on a
  target the operator hasn't attested they're authorized to test.
- **+** Deny-by-default + exclusions-win mirror how real rules-of-engagement and
  bug-bounty scopes work, so the model maps to reality.
- **+** The attestation is a human accountability record findings can reference.
- **−** It intentionally can't do anything offensive on its own yet — that's the
  point. Capabilities are added on top of the gate, never around it.
- **Non-goals:** autonomous exploitation of arbitrary targets, or any capability
  that bypasses the scope gate. Those will not be built.
