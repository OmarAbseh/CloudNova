"""Mentor progress tracking: persistence, next-step logic, prereq gating."""

import pytest

from cloudnova.range.mentor import progress


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDNOVA_CONFIG_DIR", str(tmp_path))


def test_starts_empty():
    assert progress.completed() == set()
    assert progress.summary().done == 0


def test_mark_done_persists():
    progress.mark_done("foundations")
    assert "foundations" in progress.completed()
    assert progress.summary().done == 1


def test_unknown_module_rejected():
    with pytest.raises(KeyError):
        progress.mark_done("nope")


def test_next_is_a_prereq_free_module_first():
    nxt = progress.next_modules(1)
    assert nxt and not nxt[0].prereqs  # foundations-level, no prereqs


def test_next_advances_after_completion():
    first = progress.next_modules(1)[0].id
    progress.mark_done(first)
    second = progress.next_modules(1)[0].id
    assert second != first


def test_next_respects_prereqs():
    # A module with prereqs shouldn't appear until its prereqs are done.
    from cloudnova.range.mentor.curriculum import get_module

    ad = get_module("active-directory")
    ready_ids = {m.id for m in progress.next_modules(99)}
    assert "active-directory" not in ready_ids  # its prereqs aren't done yet
    assert ad.prereqs  # sanity: it does have prereqs


def test_reset():
    progress.mark_done("foundations")
    progress.reset()
    assert progress.completed() == set()
