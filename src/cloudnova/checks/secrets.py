"""Secret scanning: find hardcoded credentials in any scanned file.

Unlike the resource checks, this is a *universal* check (``target = "*"``): the
engine runs it on every artifact's raw text regardless of format, because a
leaked key is just as dangerous in a Terraform file, a Kubernetes manifest, or a
plain config. Patterns are deliberately high-precision (AWS key formats, PEM
private-key headers, provider token prefixes) to keep false positives low, and
evidence is redacted so the report never re-leaks the secret.

This is personal for CloudNova: the original thesis committed a live API key.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from cloudnova.core.artifact import Artifact
from cloudnova.core.check import Check, register
from cloudnova.core.findings import Confidence, Finding, Location, Severity


class _Pattern:
    """A named secret pattern with its own severity and confidence."""

    def __init__(self, name: str, regex: str, severity: Severity, confidence: Confidence) -> None:
        self.name = name
        self.regex = re.compile(regex)
        self.severity = severity
        self.confidence = confidence


# High-signal patterns. Ordered most- to least-specific; each line is scanned
# against all of them.
_PATTERNS: tuple[_Pattern, ...] = (
    _Pattern(
        "AWS access key ID", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", Severity.CRITICAL, Confidence.HIGH
    ),
    _Pattern(
        "Private key block",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        Severity.CRITICAL,
        Confidence.HIGH,
    ),
    _Pattern("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", Severity.HIGH, Confidence.HIGH),
    _Pattern("Slack token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", Severity.HIGH, Confidence.HIGH),
    _Pattern("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b", Severity.HIGH, Confidence.MEDIUM),
    _Pattern(
        "Generic API key assignment",
        r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9/+=_\-]{16,}['\"]",
        Severity.MEDIUM,
        Confidence.LOW,
    ),
)


def _redact(text: str) -> str:
    """Show only the first few characters so the report never re-leaks a secret."""
    text = text.strip()
    if len(text) <= 8:
        return "****"
    return f"{text[:4]}…{text[-2:]} ({len(text)} chars)"


@register
class SecretScan(Check):
    id = "SECRET_HARDCODED"
    title = "Hardcoded secret detected"
    severity = Severity.CRITICAL
    target = "*"

    def run(self, artifact: Artifact) -> Iterator[Finding]:
        if not artifact.raw:
            return
        seen: set[tuple[str, int]] = set()
        for lineno, line in enumerate(artifact.raw.splitlines(), start=1):
            for pattern in _PATTERNS:
                match = pattern.regex.search(line)
                if match is None:
                    continue
                key = (pattern.name, lineno)
                if key in seen:
                    continue
                seen.add(key)
                yield Finding(
                    check_id=self.id,
                    title=f"{self.title}: {pattern.name}",
                    severity=pattern.severity,
                    confidence=pattern.confidence,
                    location=Location(path=artifact.path, line=lineno),
                    description=(
                        f"A value matching '{pattern.name}' appears in this file. Hardcoded "
                        "credentials in source control are a top cause of cloud compromise."
                    ),
                    remediation=(
                        "Remove the secret, rotate it immediately, and load it at runtime from a "
                        "secrets manager or environment variable. Add the file to .gitignore."
                    ),
                    evidence=_redact(match.group(0)),
                    cis_controls=["CIS AWS 1.4"],
                    mitre_attack=["T1552"],  # Unsecured Credentials
                )
