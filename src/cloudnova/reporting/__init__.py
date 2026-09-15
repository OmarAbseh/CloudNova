"""Output formatters: turn a ScanResult into console / JSON / SARIF text."""

from cloudnova.reporting.console import render_console
from cloudnova.reporting.json_report import render_json

__all__ = ["render_console", "render_json"]
