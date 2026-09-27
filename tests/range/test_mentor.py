"""Mentor: curriculum integrity, learning-path ordering, cert/job tracks, gated labs."""

import pytest

from cloudnova.range import mentor
from cloudnova.range.mentor.coach import CERT_TRACKS, JOB_LEVELS
from cloudnova.range.mentor.curriculum import Level, all_modules
from cloudnova.range.scope import Authorization, Scope


def test_curriculum_ids_unique():
    ids = [m.id for m in all_modules()]
    assert len(ids) == len(set(ids))


def test_every_prereq_exists():
    ids = {m.id for m in all_modules()}
    for m in all_modules():
        for p in m.prereqs:
            assert p in ids, f"{m.id} has unknown prereq {p}"


def test_learning_path_respects_prereqs():
    order = {step.module.id: step.order for step in mentor.learning_path()}
    for m in all_modules():
        for p in m.prereqs:
            assert order[p] < order[m.id], f"{p} must come before {m.id}"


def test_learning_path_level_cap():
    ids = {s.module.id for s in mentor.learning_path(Level.JUNIOR)}
    # A senior module must not appear when capped at junior.
    assert "active-directory" not in ids
    assert "foundations" in ids


def test_cert_tracks_reference_real_modules():
    ids = {m.id for m in all_modules()}
    for cert, modules in CERT_TRACKS.items():
        for mid in modules:
            assert mid in ids, f"{cert} references unknown module {mid}"


def test_cert_track_is_prereq_ordered():
    track = mentor.cert_track("OSCP")
    order = {m.id: i for i, m in enumerate(track)}
    for m in track:
        for p in m.prereqs:
            if p in order:
                assert order[p] < order[m.id]


def test_cert_track_case_insensitive():
    assert mentor.cert_track("oscp") == mentor.cert_track("OSCP")


def test_unknown_cert_raises():
    with pytest.raises(KeyError):
        mentor.cert_track("NOTACERT")


def test_job_levels_reference_real_modules():
    ids = {m.id for m in all_modules()}
    for level, modules in JOB_LEVELS.items():
        for mid in modules:
            assert mid in ids, f"job level {level} references unknown module {mid}"


def test_job_track_junior_is_subset_of_senior():
    junior = {m.id for m in mentor.job_track("junior")}
    senior = {m.id for m in mentor.job_track("senior")}
    assert junior < senior


def test_certs_for_module():
    assert "OSCP" in mentor.certs_for("privesc-linux")


def _scope(in_scope, out=None):
    return Scope(
        authorization=Authorization("Prog", "policy", acknowledged=True),
        in_scope=in_scope,
        out_of_scope=out or [],
    )


def test_lab_session_gated_allow():
    plan = mentor.start_lab_session("api.example.com", _scope(["*.example.com"]))
    assert plan.authorized
    assert plan.phases  # methodology provided


def test_lab_session_gated_deny():
    plan = mentor.start_lab_session("evil.com", _scope(["*.example.com"]))
    assert not plan.authorized
    assert plan.phases == []  # no plan for unauthorized targets


def test_lab_session_denies_unattested_scope():
    unattested = Scope(
        authorization=Authorization("", "", acknowledged=False), in_scope=["*.example.com"]
    )
    assert not mentor.start_lab_session("api.example.com", unattested).authorized
