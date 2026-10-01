"""Config resolution: env wins over .env, and absence means local mode."""

from __future__ import annotations

from cloudnova.platform.config import load_config, load_env_file, service_role_key_present


def test_unconfigured_returns_none(tmp_path):
    assert load_config({}, env_file=tmp_path / "nope.env") is None


def test_partial_config_is_not_enough(tmp_path):
    # A URL with no key cannot authenticate anyone; treat it as unconfigured
    # rather than half-starting multi-tenant mode.
    env = {"SUPABASE_URL": "https://proj.supabase.co"}
    assert load_config(env, env_file=tmp_path / "nope.env") is None


def test_reads_from_environment(tmp_path):
    cfg = load_config(
        {"SUPABASE_URL": "https://proj.supabase.co/", "SUPABASE_ANON_KEY": "k"},
        env_file=tmp_path / "nope.env",
    )
    assert cfg is not None
    # Trailing slash stripped so url building never doubles up.
    assert cfg.url == "https://proj.supabase.co"
    assert cfg.auth_url == "https://proj.supabase.co/auth/v1"
    assert cfg.rest_url == "https://proj.supabase.co/rest/v1"


def test_falls_back_to_env_file(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# a comment\n"
        "SUPABASE_URL=https://fromfile.supabase.co\n"
        'SUPABASE_ANON_KEY="quoted-key"\n'
        "\n",
        encoding="utf-8",
    )
    cfg = load_config({}, env_file=env_file)
    assert cfg is not None
    assert cfg.url == "https://fromfile.supabase.co"
    assert cfg.anon_key == "quoted-key"


def test_real_environment_beats_env_file(tmp_path):
    # A stale .env in the working directory must never override what the
    # hosting platform injected.
    env_file = tmp_path / ".env"
    env_file.write_text("SUPABASE_URL=https://stale\nSUPABASE_ANON_KEY=stale\n", encoding="utf-8")
    cfg = load_config(
        {"SUPABASE_URL": "https://live", "SUPABASE_ANON_KEY": "live"}, env_file=env_file
    )
    assert cfg is not None
    assert cfg.url == "https://live"
    assert cfg.anon_key == "live"


def test_env_file_parsing_edge_cases(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "PLAIN=value\n"
        "  SPACED  =  padded  \n"
        "EMPTY=\n"
        "NOEQUALS\n"
        "#COMMENT=ignored\n"
        "URL=https://x/y?a=b\n",  # value containing '=' survives intact
        encoding="utf-8",
    )
    values = load_env_file(env_file)
    assert values["PLAIN"] == "value"
    assert values["SPACED"] == "padded"
    assert values["EMPTY"] == ""
    assert values["URL"] == "https://x/y?a=b"
    assert "NOEQUALS" not in values
    assert "#COMMENT" not in values


def test_missing_env_file_is_empty(tmp_path):
    assert load_env_file(tmp_path / "absent") == {}


def test_service_role_key_detection(tmp_path):
    assert service_role_key_present({}, env_file=tmp_path / "nope") is False
    assert service_role_key_present({"SUPABASE_SERVICE_ROLE_KEY": "s"}, env_file=tmp_path / "nope")
