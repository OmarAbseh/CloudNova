"""CloudNova Range — Mentor: a structured pentest tutor.

Turns the curriculum into a personalised learning path, certification tracks, and
job-readiness maps, plus scope-gated guided lab sessions for practice targets.
Knowledge/coaching is safe and ungated; anything that names a *target* to work
against goes through the Range scope engine first.
"""

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

__all__ = [
    "CERT_TRACKS",
    "CURRICULUM",
    "JOB_LEVELS",
    "LabPlan",
    "Level",
    "Module",
    "all_modules",
    "cert_track",
    "certs_for",
    "get_module",
    "job_track",
    "learning_path",
    "start_lab_session",
]
