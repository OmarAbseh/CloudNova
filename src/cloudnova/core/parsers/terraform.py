"""Parse Terraform HCL into normalized :class:`CloudResource` objects.

python-hcl2 (v8) preserves string literals with their surrounding quotes and
tags blocks with ``__is_block__`` for round-tripping. We normalize both away so
checks see clean Python data. A parse failure raises :class:`TerraformParseError`
which the loader turns into a recorded scan error — never a crash.
"""

from __future__ import annotations

import io
from typing import Any

import hcl2

from cloudnova.core.resource import CloudResource, IaCFormat


class TerraformParseError(Exception):
    """Raised when HCL cannot be parsed."""


def _dequote(value: Any) -> Any:
    """Strip the surrounding double quotes python-hcl2 keeps on string literals."""
    if isinstance(value, str) and len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _normalize(obj: Any) -> Any:
    """Recursively dequote strings and drop hcl2's ``__is_block__`` markers."""
    if isinstance(obj, dict):
        return {_dequote(k): _normalize(v) for k, v in obj.items() if k != "__is_block__"}
    if isinstance(obj, list):
        return [_normalize(v) for v in obj]
    return _dequote(obj)


def resolve_jsonencode(value: Any) -> Any:
    """Best-effort decode of a Terraform ``jsonencode({...})`` expression.

    hcl2 leaves ``jsonencode(...)`` as an interpolation string whose argument is
    an HCL object literal (``{Key = "v"}``), not JSON. We extract the argument
    and re-parse it as HCL so IAM-policy checks can inspect the real structure.
    Returns the input unchanged if it is not a jsonencode expression or cannot be
    resolved — callers must tolerate a plain string.
    """
    if not isinstance(value, str) or "jsonencode(" not in value:
        return value
    start = value.index("jsonencode(") + len("jsonencode(")
    depth = 0
    end = None
    for i in range(start, len(value)):
        if value[i] == "(":
            depth += 1
        elif value[i] == ")":
            if depth == 0:
                end = i
                break
            depth -= 1
    if end is None:
        return value
    inner = value[start:end]
    try:
        parsed = _normalize(hcl2.load(io.StringIO(f"value = {inner}")))
    except Exception:
        return value
    return parsed.get("value", value)


def parse(text: str, path: str = "<string>") -> list[CloudResource]:
    """Parse Terraform ``text`` into resources.

    hcl2 yields ``{"resource": [{type: {name: {..config..}}}, ...]}``. We flatten
    that into one :class:`CloudResource` per declared resource.
    """
    try:
        raw = hcl2.load(io.StringIO(text))
    except Exception as exc:
        raise TerraformParseError(str(exc)) from exc

    data = _normalize(raw)
    resources: list[CloudResource] = []
    for block in data.get("resource", []):
        if not isinstance(block, dict):
            continue
        for res_type, named in block.items():
            if not isinstance(named, dict):
                continue
            for name, config in named.items():
                resources.append(
                    CloudResource(
                        format=IaCFormat.TERRAFORM,
                        type=res_type,
                        name=name,
                        config=config if isinstance(config, dict) else {},
                        path=path,
                    )
                )
    return resources
