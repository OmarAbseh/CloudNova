"""Checks for generic IaC / application config files (YAML).

These are the corrected, hardened successors to the old prototype's
``config_checker``. Each rule is a small class with a stable ID, a severity, a
concrete remediation, and a compliance mapping. They inspect *parsed* data, so
they are pure functions of their input and fully unit-tested.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from cloudnova.core.artifact import Artifact
from cloudnova.core.check import Check, register
from cloudnova.core.findings import Confidence, Finding, Location, Severity


def _as_mapping(data: Any) -> dict[str, Any]:
    """Return ``data`` if it is a dict, else an empty dict.

    Guards every check against a config file whose top level is a scalar or a
    list — the exact input that made the old prototype throw ``AttributeError``.
    """
    return data if isinstance(data, dict) else {}


@register
class PublicAccessEnabled(Check):
    id = "IAC_ACCESS_PUBLIC"
    title = "Resource exposes public access"
    severity = Severity.HIGH
    target = "iac_config"

    def run(self, artifact: Artifact) -> Iterator[Finding]:
        cfg = _as_mapping(artifact.data)
        access = _as_mapping(cfg.get("access_control"))
        if access.get("public") is True:
            yield Finding(
                check_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.HIGH,
                location=Location(path=artifact.path, resource="access_control.public"),
                description=(
                    "access_control.public is set to true, which exposes the "
                    "resource to anyone on the internet."
                ),
                remediation="Set access_control.public to false and grant access by role instead.",
                evidence="access_control.public: true",
                references=[
                    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
                ],
                cis_controls=["CIS AWS 1.20"],
                mitre_attack=["T1530"],  # Data from Cloud Storage Object
            )


@register
class PasswordAuthDisabled(Check):
    id = "IAC_AUTH_NO_PASSWORD"
    title = "Password authentication disabled"
    severity = Severity.MEDIUM
    target = "iac_config"

    def run(self, artifact: Artifact) -> Iterator[Finding]:
        cfg = _as_mapping(artifact.data)
        auth = _as_mapping(cfg.get("authentication"))
        # Only flag an explicit `false` — a missing key is not evidence of a
        # weakness and would be a false positive.
        if auth.get("password_required") is False:
            yield Finding(
                check_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.HIGH,
                location=Location(path=artifact.path, resource="authentication.password_required"),
                description=(
                    "authentication.password_required is false, so credentials are not enforced."
                ),
                remediation=(
                    "Set authentication.password_required to true "
                    "(or require a stronger factor such as MFA)."
                ),
                evidence="authentication.password_required: false",
                cis_controls=["CIS AWS 1.5"],
                mitre_attack=["T1078"],  # Valid Accounts
            )


@register
class NoSessionTimeout(Check):
    id = "IAC_SESSION_NO_TIMEOUT"
    title = "Session timeout disabled or missing"
    severity = Severity.LOW
    target = "iac_config"

    def run(self, artifact: Artifact) -> Iterator[Finding]:
        cfg = _as_mapping(artifact.data)
        session = _as_mapping(cfg.get("session"))
        if "timeout" not in session:
            return
        timeout = session.get("timeout")
        # A timeout of 0 means "never expire"; a non-numeric value is a
        # misconfiguration we surface rather than crash on.
        if not isinstance(timeout, (int, float)):
            confidence, detail = Confidence.MEDIUM, f"non-numeric timeout ({timeout!r})"
        elif timeout <= 0:
            confidence, detail = Confidence.HIGH, "timeout of 0 disables session expiry"
        else:
            return
        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=confidence,
            location=Location(path=artifact.path, resource="session.timeout"),
            description=(
                f"Session timeout is misconfigured: {detail}. Idle sessions can be hijacked."
            ),
            remediation="Set session.timeout to a positive number of minutes (e.g. 15).",
            evidence=f"session.timeout: {timeout!r}",
            mitre_attack=["T1563"],  # Remote Service Session Hijacking
        )
