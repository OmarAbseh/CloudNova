"""Toolkit: orchestrate real security tools, scope-gated, output -> Findings.

CloudNova drives industry-standard tools (nmap, nuclei, ffuf) rather than
reimplementing them, authorizes every target through the scope engine first, and
normalizes each tool's output into the shared Finding contract. Adapters cover
recon and detection; aggressive tools require explicit operator confirmation.
"""

from cloudnova.range.toolkit import ffuf, nmap, nuclei
from cloudnova.range.toolkit.base import (
    CommandResult,
    ToolError,
    ToolResult,
    ToolTier,
    is_installed,
)

# Registry of available adapters for discovery/listing.
ADAPTERS: dict[str, str] = {
    "nmap": "Service/port discovery (ACTIVE).",
    "nuclei": "Template-based vulnerability checks (ACTIVE).",
    "ffuf": "Content/endpoint discovery (ACTIVE).",
}

__all__ = [
    "ADAPTERS",
    "CommandResult",
    "ToolError",
    "ToolResult",
    "ToolTier",
    "ffuf",
    "is_installed",
    "nmap",
    "nuclei",
]
