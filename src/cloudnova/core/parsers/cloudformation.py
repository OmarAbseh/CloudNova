"""Parse CloudFormation templates (JSON or YAML) into :class:`CloudResource`.

CloudFormation YAML uses short-form intrinsic tags (``!Ref``, ``!GetAtt``,
``!Sub`` …) that vanilla ``yaml.safe_load`` rejects. We register a multi
constructor that turns each into its canonical ``{"Fn::<name>": value}`` (or
``{"Ref": value}``) mapping, so downstream checks see plain data and are never
tripped by the tag syntax.
"""

from __future__ import annotations

import json
from typing import Any

import yaml

from cloudnova.core.resource import CloudResource, IaCFormat


class CloudFormationParseError(Exception):
    """Raised when a template cannot be parsed."""


class _CfnLoader(yaml.SafeLoader):
    """SafeLoader that understands CloudFormation intrinsic short-form tags."""


def _construct_intrinsic(loader: _CfnLoader, tag_suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    elif isinstance(node, yaml.MappingNode):
        value = loader.construct_mapping(node)
    else:  # pragma: no cover — pyyaml only emits the three node types above
        value = None
    # !Ref maps to {"Ref": ...}; everything else to {"Fn::<Name>": ...}.
    key = "Ref" if tag_suffix == "Ref" else f"Fn::{tag_suffix}"
    return {key: value}


_CfnLoader.add_multi_constructor("!", _construct_intrinsic)


def looks_like_cloudformation(data: Any) -> bool:
    """Heuristic: a mapping with a ``Resources`` dict whose entries carry ``Type``.

    Matches real templates while rejecting generic configs and Kubernetes
    manifests (which have ``apiVersion`` + ``kind`` instead).
    """
    if not isinstance(data, dict):
        return False
    resources = data.get("Resources")
    if not isinstance(resources, dict) or not resources:
        return False
    return any(isinstance(v, dict) and "Type" in v for v in resources.values())


def parse_data(data: Any, path: str = "<string>") -> list[CloudResource]:
    """Turn an already-parsed template mapping into resources."""
    resources: list[CloudResource] = []
    if not isinstance(data, dict):
        return resources
    for logical_id, body in data.get("Resources", {}).items():
        if not isinstance(body, dict):
            continue
        res_type = body.get("Type")
        if not isinstance(res_type, str):
            continue
        props = body.get("Properties")
        resources.append(
            CloudResource(
                format=IaCFormat.CLOUDFORMATION,
                type=res_type,
                name=str(logical_id),
                config=props if isinstance(props, dict) else {},
                path=path,
            )
        )
    return resources


def load_template(text: str) -> Any:
    """Parse template text (JSON first, then CFN-aware YAML) into a mapping."""
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise CloudFormationParseError(str(exc)) from exc
    try:
        return yaml.load(text, Loader=_CfnLoader)
    except yaml.YAMLError as exc:
        raise CloudFormationParseError(str(exc)) from exc


def load_all(text: str) -> list[Any]:
    """Parse every YAML document in ``text`` with the CFN-aware safe loader.

    Shared by the loader for all ``.yaml``/``.yml`` inputs: it tolerates CFN
    intrinsic tags *and* multi-document manifests (Kubernetes), so one parse
    serves every YAML dialect we classify.
    """
    try:
        return [doc for doc in yaml.load_all(text, Loader=_CfnLoader) if doc is not None]
    except yaml.YAMLError as exc:
        raise CloudFormationParseError(str(exc)) from exc


def parse(text: str, path: str = "<string>") -> list[CloudResource]:
    """Parse CloudFormation ``text`` into resources."""
    return parse_data(load_template(text), path)
