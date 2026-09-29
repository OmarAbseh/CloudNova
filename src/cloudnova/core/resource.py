"""The normalized cloud-resource model.

Terraform, CloudFormation, and Kubernetes describe the same underlying cloud
objects in three different dialects. Rather than write three parallel rule sets,
every IaC parser normalizes its input into :class:`CloudResource` objects, and
checks reason over those. This is the seam that lets one rule (e.g. "S3 bucket
is public") work regardless of which format declared the bucket — and it is the
same node type the Phase 3 attack-path graph will be built from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class IaCFormat(StrEnum):
    """Which dialect a resource was parsed from (for provenance + reporting)."""

    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"
    KUBERNETES = "kubernetes"


@dataclass(frozen=True, slots=True)
class CloudResource:
    """One declared cloud resource, normalized across IaC formats.

    ``type`` keeps the dialect-native type string (``aws_s3_bucket``,
    ``AWS::S3::Bucket``, ``Deployment``) because checks are written against a
    specific provider's vocabulary — normalizing the *shape* (a resource with a
    name, a type, and a config dict) is what buys reuse, not flattening the type
    names into a lossy common denominator.
    """

    format: IaCFormat
    type: str
    name: str
    config: dict[str, Any]
    path: str
    line: int | None = None
    #: Free-form provenance, e.g. the module or namespace the resource lives in.
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def address(self) -> str:
        """A stable, human-readable id, e.g. ``aws_s3_bucket.data``."""
        return f"{self.type}.{self.name}"

    def get(self, key: str, default: Any = None) -> Any:
        """Convenience accessor into the resource's config dict."""
        return self.config.get(key, default)
