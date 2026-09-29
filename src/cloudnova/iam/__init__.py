"""IAM authoring and analysis.

Two complementary capabilities:

- :mod:`cloudnova.iam.analyzer` audits an IAM policy document for anti-patterns
  and known privilege-escalation vectors.
- :mod:`cloudnova.iam.generator` authors a least-privilege policy from a
  high-level grant spec.

Together they let CloudNova both *write* scoped IAM and *prove* a policy (yours or
generated) is free of the dangerous patterns — the generator's output is
validated by the analyzer in tests.
"""

from cloudnova.iam.analyzer import analyze_policy
from cloudnova.iam.generator import GenerationError, generate_policy

__all__ = ["GenerationError", "analyze_policy", "generate_policy"]
