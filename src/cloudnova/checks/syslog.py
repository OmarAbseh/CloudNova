"""Checks for authentication logs (syslog / auth.log style).

The old prototype emitted one finding *per matching line*, so a real log with
500 failed logins produced 500 unreadable cards and never actually detected the
"duplicate IP" brute-force pattern its README advertised. This version
aggregates: it counts failures per source IP and raises a *single* finding per
offending IP, with the count as evidence and severity scaled by volume.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator

from cloudnova.core.artifact import Artifact
from cloudnova.core.check import Check, register
from cloudnova.core.findings import Confidence, Finding, Location, Severity

# "Failed password for [invalid user] <user> from <ip> port ..."
_FAILED_RE = re.compile(r"Failed password for (?:invalid user )?\S+ from (\d{1,3}(?:\.\d{1,3}){3})")

#: Failed attempts from one IP above which we treat it as a brute-force attempt.
_BRUTE_FORCE_THRESHOLD = 5


@register
class SshBruteForce(Check):
    id = "LOG_SSH_BRUTE_FORCE"
    title = "Repeated SSH authentication failures (possible brute force)"
    severity = Severity.MEDIUM
    target = "syslog"

    def run(self, artifact: Artifact) -> Iterator[Finding]:
        text = artifact.data if isinstance(artifact.data, str) else ""
        counts: Counter[str] = Counter(_FAILED_RE.findall(text))

        for ip, count in counts.most_common():
            if count < 2:
                continue
            # Volume drives severity: a handful is noise, hundreds is an attack.
            if count >= _BRUTE_FORCE_THRESHOLD:
                severity, confidence = Severity.HIGH, Confidence.HIGH
            else:
                severity, confidence = Severity.MEDIUM, Confidence.MEDIUM
            yield Finding(
                check_id=self.id,
                title=self.title,
                severity=severity,
                confidence=confidence,
                location=Location(path=artifact.path, resource=ip),
                description=(
                    f"{count} failed SSH password attempts originated from {ip}. "
                    "Repeated failures from a single source indicate credential "
                    "stuffing or brute forcing."
                ),
                remediation=(
                    f"Block or rate-limit {ip} (fail2ban / security group), enforce key-based "
                    "SSH auth, and disable password login."
                ),
                evidence=f"{count} failed attempts from {ip}",
                mitre_attack=["T1110"],  # Brute Force
            )
