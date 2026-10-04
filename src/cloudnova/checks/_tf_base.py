"""Shared plumbing for the Terraform rule packs.

The rule packs are split by what an attacker is after rather than by AWS
service, because that is how the findings get triaged: data at rest, network
exposure, compute identity, logging. A reader fixing an exposure problem wants
every exposure rule together, not S3 next to CloudFront because both begin
with C.
"""

from __future__ import annotations

from abc import abstractmethod
from collections.abc import Iterator
from typing import Any

from cloudnova.core.artifact import Artifact
from cloudnova.core.check import Check
from cloudnova.core.findings import Finding, Location
from cloudnova.core.resource import CloudResource

# Values that mean "the whole internet" in a security group or policy.
WORLD_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


def resources(artifact: Artifact) -> list[CloudResource]:
    """Type-narrow the artifact payload to a resource list."""
    data = artifact.data
    return data if isinstance(data, list) else []


def first(value: Any) -> Any:
    """HCL blocks are often parsed as single-element lists; unwrap them."""
    if isinstance(value, list) and value:
        return value[0]
    return value


def truthy(value: Any) -> bool:
    """Terraform booleans arrive as bool, "true"/"false", or 1/0."""
    value = first(value)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1", "enabled", "on"}
    if isinstance(value, (int, float)):
        return bool(value)
    return False


def missing(value: Any) -> bool:
    """True when an attribute is absent or explicitly empty.

    Absence matters as much as a wrong value: a block that is simply not there
    is the most common way encryption and logging end up off.
    """
    value = first(value)
    return value is None or value == "" or value == [] or value == {}


class TerraformCheck(Check):
    """Base for terraform checks: fixes the target and iterates resources."""

    target = "terraform"

    def run(self, artifact: Artifact) -> Iterator[Finding]:
        for resource in resources(artifact):
            yield from self.check_resource(resource)

    @abstractmethod
    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        """Yield findings for a single resource."""
        raise NotImplementedError

    def loc(self, resource: CloudResource) -> Location:
        return Location(path=resource.path, resource=resource.address, line=resource.line)


class AttributeCheck(TerraformCheck):
    """A check that fires when one attribute on one resource type is wrong.

    Most hardening rules have this shape, so expressing them as data keeps the
    rule packs readable: the interesting part of a rule is its description and
    its mapping, not another copy of the same loop.
    """

    #: Resource types this rule applies to.
    types: frozenset[str] = frozenset()
    #: Attribute whose absence or falseness is the problem.
    attribute: str = ""
    #: Shown as the offending value.
    description_template: str = ""
    remediation_text: str = ""
    cis: tuple[str, ...] = ()
    mitre: tuple[str, ...] = ()
    #: When True the finding fires if the attribute is truthy instead of falsey.
    invert: bool = False

    def _violated(self, resource: CloudResource) -> bool:
        raw = resource.get(self.attribute)
        if self.invert:
            return truthy(raw)
        return missing(raw) or not truthy(raw)

    def check_resource(self, resource: CloudResource) -> Iterator[Finding]:
        if resource.type not in self.types:
            return
        if not self._violated(resource):
            return
        from cloudnova.core.findings import Confidence

        yield Finding(
            check_id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=Confidence.HIGH,
            location=self.loc(resource),
            description=self.description_template.format(name=resource.name, type=resource.type),
            remediation=self.remediation_text,
            evidence=f"{self.attribute} is "
            + ("set" if self.invert else "absent or false")
            + f" on {resource.type}",
            cis_controls=list(self.cis),
            mitre_attack=list(self.mitre),
        )
