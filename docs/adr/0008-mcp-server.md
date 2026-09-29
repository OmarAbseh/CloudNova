# 0008 — Expose CloudNova to AI agents via an MCP server

**Status:** Accepted

## Context
The roadmap's endgame is AI agents that reason about findings like a pentester.
Rather than bake an LLM into the scanner, the leverage is to make CloudNova
*callable by* any agent — so Claude (or any MCP client) can scan infrastructure
and reason about the results as part of a larger investigation.

## Decision
Ship a Model Context Protocol server (`cloudnova-mcp`) exposing three tools:
`scan`, `list_checks`, and `attack_paths`. All logic lives in a plain-dict
`cloudnova.service` module; the MCP module is a thin adapter. `mcp` is an
optional extra (`pip install cloudnova[mcp]`), and the server class is resolved
dynamically because the SDK renamed `FastMCP` → `MCPServer` in v2.

## Consequences
- **+** An agent can drive CloudNova: "scan this repo, explain the worst attack
  path, propose the fix." The `Finding`/service dicts are already its input format.
- **+** `service.py` is a clean programmatic API reusable by a future web API too,
  and is fully unit-tested without needing an MCP client.
- **+** Core install stays lean; only users who want the server pull `mcp`.
- **−** The adapter is dynamically typed (the SDK's decorator is untyped); mypy
  strictness is relaxed for that one module only, not the tested service logic.
