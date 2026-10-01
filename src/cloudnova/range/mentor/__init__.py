"""CloudNova Range - Mentor: a structured pentest tutor.

Turns the curriculum into a personalised learning path, certification tracks, and
job-readiness maps, plus scope-gated guided lab sessions for practice targets.
Knowledge/coaching is safe and ungated; anything that names a *target* to work
against goes through the Range scope engine first.
"""

from cloudnova.range.mentor.advisor import Answer, ask
from cloudnova.range.mentor.coach import (
    CERT_TRACKS,
    JOB_LEVELS,
    cert_track,
    certs_for,
    job_track,
    learning_path,
)
from cloudnova.range.mentor.curriculum import CURRICULUM, Level, Module, all_modules, get_module
from cloudnova.range.mentor.lab import LabPlan, start_lab_session
from cloudnova.range.mentor.progress import (
    completed,
    mark_done,
    mark_undone,
    next_modules,
    reset,
    summary,
)

__all__ = [
    "CERT_TRACKS",
    "CURRICULUM",
    "JOB_LEVELS",
    "Answer",
    "LabPlan",
    "Level",
    "Module",
    "all_modules",
    "ask",
    "cert_track",
    "certs_for",
    "completed",
    "get_module",
    "job_track",
    "learning_path",
    "mark_done",
    "mark_undone",
    "next_modules",
    "reset",
    "start_lab_session",
    "summary",
]
