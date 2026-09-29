"""Blackbox pentest checklist (PTES + OWASP WSTG) for CloudNova Range.

Runs the methodology against an authorized target: passive items are checked
automatically, opt-in ``--active`` items are detected (non-destructively), and
manual items are tracked with guidance. Renders an engagement report in the
DarkShield layout with a vulnerability summary table.
"""

from cloudnova.range.checklist.blackbox import BLACKBOX_CHECKLIST, phases
from cloudnova.range.checklist.model import ChecklistItem, ChecklistRun, Mode, RunItem, State
from cloudnova.range.checklist.report import render_report, summary_counts
from cloudnova.range.checklist.runner import run_checklist

__all__ = [
    "BLACKBOX_CHECKLIST",
    "ChecklistItem",
    "ChecklistRun",
    "Mode",
    "RunItem",
    "State",
    "phases",
    "render_report",
    "run_checklist",
    "summary_counts",
]
