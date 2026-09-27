"""Operator personas: selection, persistence, env override — cosmetic only."""

import pytest

from cloudnova.range import persona


@pytest.fixture(autouse=True)
def _isolated_config(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDNOVA_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("CLOUDNOVA_PERSONA", raising=False)


def test_default_is_cloudnova():
    assert persona.active_persona().id == "cloudnova"


def test_builtin_personas_present():
    ids = {p.id for p in persona.list_personas()}
    assert {"cloudnova", "gh0st"} <= ids


def test_set_active_persists():
    persona.set_active("gh0st")
    assert persona.active_persona().id == "gh0st"
    assert persona.active_persona().handle == "gh0st"


def test_env_var_overrides_saved(monkeypatch):
    persona.set_active("gh0st")
    monkeypatch.setenv("CLOUDNOVA_PERSONA", "cloudnova")
    assert persona.active_persona().id == "cloudnova"


def test_unknown_persona_rejected():
    with pytest.raises(KeyError):
        persona.set_active("nobody")


def test_unknown_saved_falls_back_to_default(tmp_path):
    (tmp_path / "persona").write_text("bogus\n", encoding="utf-8")
    assert persona.active_persona().id == "cloudnova"


def test_banner():
    assert "gh0st" in persona.get_persona("gh0st").banner()
