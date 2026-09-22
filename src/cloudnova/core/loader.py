"""Turn files on disk into :class:`Artifact` objects.

This is the *only* layer that touches the filesystem. It classifies a file by
extension + content, parses it safely, and hands the engine typed artifacts.
Parsing errors become :class:`LoadError` rather than crashing a scan — one
malformed file must never take down the whole run (a lesson from the old
prototype, where any bad input threw a 500).

Classification is two-stage: the extension picks a parser, then *content*
refines the kind — a ``.json`` or ``.yaml`` file may be a CloudFormation
template, a CloudTrail log, or a generic config, and only its contents can say.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from cloudnova.core.artifact import Artifact
from cloudnova.core.parsers import cloudformation, terraform

#: File extensions we know how to parse. The value is the *default* kind; content
#: classification may override it (see :func:`_classify`).
_SUFFIX_KINDS: dict[str, str] = {
    ".yaml": "iac_config",
    ".yml": "iac_config",
    ".json": "json_doc",
    ".log": "syslog",
    ".tf": "terraform",
    ".template": "cloudformation",
}


class LoadError(Exception):
    """Raised when a file exists but cannot be parsed."""


def _is_cloudtrail(data: object) -> bool:
    return isinstance(data, dict) and ("Records" in data or "eventName" in data)


def _classify(data: object) -> str:
    """Pick an artifact kind from parsed structured data (JSON or YAML)."""
    if cloudformation.looks_like_cloudformation(data):
        return "cloudformation"
    if _is_cloudtrail(data):
        return "cloudtrail"
    return "json_doc"


def load_file(path: Path) -> Artifact:
    """Parse a single supported file into an :class:`Artifact`.

    Raises :class:`LoadError` on unsupported types or parse failures.
    """
    suffix = path.suffix.lower()
    if suffix not in _SUFFIX_KINDS:
        raise LoadError(f"Unsupported file type: {path}")

    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        if suffix == ".log":
            # Log files stay raw text; the syslog checks tokenise per line.
            return Artifact(kind="syslog", path=str(path), data=raw, raw=raw)
        if suffix == ".tf":
            resources = terraform.parse(raw, str(path))
            return Artifact(kind="terraform", path=str(path), data=resources, raw=raw)
        if suffix == ".template":
            return _cloudformation_artifact(raw, path)

        # .json / .yaml / .yml: parse then classify by content.
        if suffix == ".json":
            data: object = json.loads(raw)
            kind = _classify(data)
        else:
            # The CFN-aware loader is a SafeLoader subclass, so it parses generic
            # YAML exactly like safe_load while also tolerating intrinsic tags.
            data = cloudformation.load_template(raw)
            kind = (
                "cloudformation" if cloudformation.looks_like_cloudformation(data) else "iac_config"
            )

        if kind == "cloudformation":
            return _cloudformation_artifact(raw, path, preparsed=data)
        return Artifact(kind=kind, path=str(path), data=data, raw=raw)
    except (
        yaml.YAMLError,
        json.JSONDecodeError,
        terraform.TerraformParseError,
        cloudformation.CloudFormationParseError,
    ) as exc:
        raise LoadError(f"Failed to parse {path}: {exc}") from exc


def _cloudformation_artifact(raw: str, path: Path, preparsed: object | None = None) -> Artifact:
    data = preparsed if preparsed is not None else cloudformation.load_template(raw)
    resources = cloudformation.parse_data(data, str(path))
    return Artifact(kind="cloudformation", path=str(path), data=resources, raw=raw)


def discover(root: Path) -> list[Path]:
    """Return every parseable file under ``root`` (or ``root`` itself if a file)."""
    if root.is_file():
        return [root] if root.suffix.lower() in _SUFFIX_KINDS else []
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in _SUFFIX_KINDS)
