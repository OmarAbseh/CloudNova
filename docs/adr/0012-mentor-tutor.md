# 0012, Mentor: a scope-aware pentest tutor, not an autopilot

**Status:** Accepted

## Context
The goal is a mentor that takes someone from little experience to job-ready and
cert-ready in penetration testing, and stays useful long-term. The failure mode
to avoid is an "autopilot" that does the hacking so the operator never learns -
which produces neither skill nor a defensible job candidate, and invites misuse.

## Decision
`cloudnova.range.mentor` is a structured learning system, not an executor:

- **Curriculum** as data, a prereq-linked skill tree (foundations → web/Burp →
  privesc → AD → cloud → reporting), each module mapped to tools, legitimate
  practice resources (PortSwigger Academy, TryHackMe, HTB, OWASP), and certs.
- **Coach** logic, a topologically-ordered learning path, certification prep
  tracks (eJPT/PNPT/OSCP/CEH/eWPT) built from each cert's published domains, and
  job-level readiness maps (junior/mid/senior).
- **Guided labs**, methodology walkthroughs that name a *practice target* and
  therefore pass through the Range scope engine first; unauthorized targets are
  refused and get no plan.

Content is methodology- and learning-oriented (how to think and how to use the
tools), the same material industry certs teach, pointed at authorized/practice
targets.

## Consequences
- **+** Teaches the operator to *become* competent, which is what actually earns a
  job and a cert, and what keeps the tool legitimate.
- **+** Everything that names a target reuses the one authorization gate (ADR 0011).
- **+** Pure data+logic: fully testable offline; an AI-backed "explain deeper"
  layer can sit on top at runtime without changing the structure.
- **+** The mentor guides; the human operates and learns.
