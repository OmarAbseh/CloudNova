"""Core data model for CloudNova.

Everything the scanner produces is a :class:`Finding`. Keeping one strongly
typed, validated shape for every check — instead of ad-hoc dicts — is what lets
us render to any format, diff two scans, feed an AI agent, and enforce a schema
in tests. This is the contract the whole rest of the codebase depends on.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """How bad a finding is if left unaddressed.

    Ordered enum so we can sort and threshold on it (see :meth:`rank`).
    Mirrors the vocabulary used by CVSS bands and most cloud-security tools.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric weight, higher = more severe. Used for sorting/scoring."""
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }[self]


class Confidence(StrEnum):
    """How sure the check is that this is a true positive.

    A substring match on a bucket name is LOW confidence; parsing an IAM
    policy document and finding ``Action: "*"`` is HIGH. Surfacing confidence
    separately from severity is what stops a scanner from crying wolf — the old
    prototype flagged any bucket *named* "public" with no such distinction.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Location(BaseModel):
    """Where a finding lives, so a human (or an autofix) can go fix it."""

    path: str = Field(description="File path or cloud resource ARN/ID.")
    line: int | None = Field(default=None, description="1-indexed line, if known.")
    resource: str | None = Field(
        default=None, description="Logical resource name, e.g. 'aws_s3_bucket.data'."
    )


class Finding(BaseModel):
    """A single security issue discovered by a check.

    Immutable once created. The ``check_id`` ties it back to the rule that
    produced it; ``references`` and ``remediation`` make it actionable; the
    optional framework mappings (CIS/MITRE) make it audit-ready.
    """

    model_config = {"frozen": True}

    check_id: str = Field(description="Stable ID of the rule, e.g. 'IAC_S3_PUBLIC_ACL'.")
    title: str = Field(description="One-line human summary.")
    severity: Severity
    confidence: Confidence = Confidence.HIGH
    location: Location
    description: str = Field(description="What is wrong and why it matters.")
    remediation: str = Field(description="Concrete steps to fix it.")

    # Optional evidence + compliance context.
    evidence: str | None = Field(default=None, description="The exact offending snippet or value.")
    references: list[str] = Field(default_factory=list, description="Docs / advisory URLs.")
    cis_controls: list[str] = Field(
        default_factory=list, description="Mapped CIS Benchmark control IDs."
    )
    mitre_attack: list[str] = Field(
        default_factory=list, description="Mapped MITRE ATT&CK technique IDs."
    )
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def sort_key(self) -> tuple[int, str, str]:
        """Deterministic ordering: most severe first, then stable by id/path."""
        return (-self.severity.rank, self.check_id, self.location.path)
