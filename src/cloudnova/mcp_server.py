"""Model Context Protocol server exposing CloudNova to AI agents.

An agent (Claude or any MCP client) can call these tools to scan infrastructure,
list the ruleset, and reason about attack paths — turning CloudNova from a CLI
into something an autonomous security agent drives.

The ``mcp`` package is an optional dependency (``pip install cloudnova[mcp]``);
the SDK renamed ``FastMCP`` to ``MCPServer`` in v2, so we support both. All real
work lives in :mod:`cloudnova.service`, keeping this module a thin adapter.
"""

from __future__ import annotations

import importlib
from typing import Any

from cloudnova import service


class MCPNotInstalledError(RuntimeError):
    """Raised when the optional ``mcp`` dependency is missing."""


# (module path, class name) for each SDK generation, newest first. The SDK
# renamed FastMCP -> MCPServer in v2; we resolve dynamically so this module
# imports cleanly whether or not (and whichever) mcp is installed.
_SERVER_CANDIDATES = (
    ("mcp.server.mcpserver", "MCPServer"),
    ("mcp.server.fastmcp", "FastMCP"),
)


def _new_server() -> Any:
    """Construct an MCP server object across SDK v1 (FastMCP) and v2 (MCPServer)."""
    for module_path, class_name in _SERVER_CANDIDATES:
        try:
            module = importlib.import_module(module_path)
        except ImportError:
            continue
        server_cls = getattr(module, class_name, None)
        if server_cls is not None:
            return server_cls(name="cloudnova")
    raise MCPNotInstalledError(
        "The 'mcp' package is required for the MCP server. "
        "Install with: pip install 'cloudnova[mcp]'"
    )


def build_server() -> Any:
    """Create the CloudNova MCP server with its tools registered.

    ``.tool()`` is the decorator in both SDK generations, so registration is
    identical regardless of which server class we got.
    """
    server = _new_server()

    @server.tool()
    def scan(
        path: str, min_severity: str | None = None, include_graph: bool = True
    ) -> dict[str, Any]:
        """Scan a file or directory for cloud-security misconfigurations.

        Returns a severity summary and the list of findings (each with severity,
        confidence, location, remediation, and CIS/MITRE mappings). Set
        ``min_severity`` (critical|high|medium|low|info) to filter, and
        ``include_graph`` to include cross-resource attack paths.
        """
        return service.scan(path, min_severity=min_severity, include_graph=include_graph)

    @server.tool()
    def list_checks() -> dict[str, Any]:
        """List every security check CloudNova can run (id, title, severity, target)."""
        return service.list_checks()

    @server.tool()
    def attack_paths(path: str) -> dict[str, Any]:
        """Find exploitable attack paths (internet-exposed → privileged/data) under a path."""
        return service.attack_paths(path)

    return server


def main() -> None:
    """Entry point: run the server over stdio (how MCP clients launch it)."""
    build_server().run()


if __name__ == "__main__":
    main()
