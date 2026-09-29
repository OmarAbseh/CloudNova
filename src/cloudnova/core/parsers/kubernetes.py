"""Parse Kubernetes manifests (YAML, possibly multi-document) into resources.

A manifest file often holds several documents separated by ``---``. Each
document with an ``apiVersion`` and a ``kind`` becomes one
:class:`CloudResource` whose ``type`` is the Kubernetes kind (``Deployment``,
``Pod``, …) and whose ``config`` is the full document, so checks can walk into
``spec`` freely.
"""

from __future__ import annotations

from typing import Any

import yaml

from cloudnova.core.resource import CloudResource, IaCFormat


class KubernetesParseError(Exception):
    """Raised when a manifest cannot be parsed."""


def load_documents(text: str) -> list[Any]:
    """Safely parse every YAML document in ``text`` (skipping empty ones)."""
    try:
        return [doc for doc in yaml.safe_load_all(text) if doc is not None]
    except yaml.YAMLError as exc:
        raise KubernetesParseError(str(exc)) from exc


def is_k8s_document(doc: Any) -> bool:
    """A Kubernetes object has both ``apiVersion`` and ``kind``."""
    return isinstance(doc, dict) and "apiVersion" in doc and "kind" in doc


def looks_like_kubernetes(docs: list[Any]) -> bool:
    """True if any document in the file is a Kubernetes object."""
    return any(is_k8s_document(d) for d in docs)


def parse_documents(docs: list[Any], path: str = "<string>") -> list[CloudResource]:
    """Turn already-parsed YAML documents into Kubernetes resources."""
    resources: list[CloudResource] = []
    for doc in docs:
        if not is_k8s_document(doc):
            continue
        metadata = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
        name = metadata.get("name", "<unnamed>")
        namespace = metadata.get("namespace", "default")
        resources.append(
            CloudResource(
                format=IaCFormat.KUBERNETES,
                type=str(doc.get("kind")),
                name=str(name),
                config=doc,
                path=path,
                meta={"namespace": namespace},
            )
        )
    return resources


def parse(text: str, path: str = "<string>") -> list[CloudResource]:
    """Parse Kubernetes manifest ``text`` into resources."""
    return parse_documents(load_documents(text), path)
