"""Data model for authorized web assessment.

The assessment is deliberately split like the rest of CloudNova: a passive
``HttpSnapshot`` (what a single non-destructive request observed) and pure
analysis functions over it. Nothing here touches the network — see ``probe`` for
the only networked code, which authorizes a target through the scope engine
before it makes any request.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cloudnova.core.findings import Confidence, Severity


@dataclass(frozen=True)
class WebFinding:
    """One observation about a web target, in the shared severity/confidence shape."""

    id: str
    title: str
    severity: Severity
    confidence: Confidence
    detail: str
    remediation: str

    def __str__(self) -> str:
        return f"[{self.severity.value.upper()}] {self.id} — {self.title}"


@dataclass(frozen=True)
class HttpSnapshot:
    """What a single non-destructive request observed. Headers are case-insensitive."""

    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)
    final_url: str = ""
    tls: bool = False

    def header(self, name: str) -> str | None:
        """Case-insensitive header lookup."""
        low = name.lower()
        for key, value in self.headers.items():
            if key.lower() == low:
                return value
        return None


@dataclass
class WebAssessment:
    """The result of assessing one authorized target."""

    target: str
    authorized: bool
    reason: str
    findings: list[WebFinding] = field(default_factory=list)
    exposed_paths: list[str] = field(default_factory=list)

    @property
    def worst(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)
