"""Output formatters: turn a ScanResult into console / JSON / SARIF text."""

from cloudnova.reporting.console import render_console
from cloudnova.reporting.json_report import render_json
from cloudnova.reporting.sarif import render_sarif

__all__ = ["render_console", "render_json", "render_sarif"]
