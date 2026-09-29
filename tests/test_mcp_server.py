"""The MCP adapter builds and registers exactly the CloudNova tools.

Skipped cleanly when the optional 'mcp' package isn't installed, so the core
test suite never depends on it.
"""

import anyio
import pytest

mcp_installed = False
try:
    import mcp  # noqa: F401

    mcp_installed = True
except ImportError:
    pass

pytestmark = pytest.mark.skipif(not mcp_installed, reason="optional 'mcp' extra not installed")


def test_server_builds_with_expected_tools():
    from cloudnova.mcp_server import build_server

    server = build_server()
    tools = anyio.run(server.list_tools)
    assert {t.name for t in tools} == {"scan", "list_checks", "attack_paths"}
