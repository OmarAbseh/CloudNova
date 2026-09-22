"""Turn files on disk into :class:`Artifact` objects.

This is the *only* layer that touches the filesystem. It classifies a file by
extension + content, parses it safely, and hands the engine typed artifacts.
Parsing errors become :class:`LoadError` rather than crashing a scan — one
malformed file must never take down the whole run (a lesson from the old
prototype, where any bad input threw a 500).
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from cloudnova.core.artifact import Artifact
from cloudnova.core.parsers import terraform

#: Files we know how to parse, mapped to the artifact kind they produce.
#: A single YAML/JSON file may be reclassified by content (e.g. CloudTrail).
_SUFFIX_KINDS: dict[str, str] = {
    ".yaml": "iac_config",
    ".yml": "iac_config",
    ".json": "json_doc",
    ".log": "syslog",
    ".tf": "terraform",
}


class LoadError(Exception):
    """Raised when a file exists but cannot be parsed."""


def _classify_json(data: object) -> str:
    """Refine a generic JSON document into a specific artifact kind.

    CloudTrail exports are ``{"Records": [...]}`` or a single event dict with an
    ``eventName``. Everything else stays a generic ``json_doc``.
    """
    if isinstance(data, dict) and ("Records" in data or "eventName" in data):
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
        if suffix == ".json":
            data = json.loads(raw)
            kind = _classify_json(data)
        else:
            # safe_load never constructs arbitrary Python objects — critical
            # when scanning untrusted config files.
            data = yaml.safe_load(raw)
            kind = "iac_config"
    except (yaml.YAMLError, json.JSONDecodeError, terraform.TerraformParseError) as exc:
        raise LoadError(f"Failed to parse {path}: {exc}") from exc

    return Artifact(kind=kind, path=str(path), data=data, raw=raw)


def discover(root: Path) -> list[Path]:
    """Return every parseable file under ``root`` (or ``root`` itself if a file)."""
    if root.is_file():
        return [root] if root.suffix.lower() in _SUFFIX_KINDS else []
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in _SUFFIX_KINDS)
