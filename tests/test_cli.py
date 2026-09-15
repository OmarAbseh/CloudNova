"""Smoke tests for the CLI surface and reporting formatters."""

import json

from typer.testing import CliRunner

from cloudnova.cli import app

runner = CliRunner()


def test_checks_command_lists_ruleset():
    result = runner.invoke(app, ["checks"])
    assert result.exit_code == 0
    assert "CT_IAM_WILDCARD_ADMIN" in result.stdout


def test_scan_json_is_valid_and_structured(tmp_path):
    (tmp_path / "c.yaml").write_text("access_control:\n  public: true\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["findings"] == 1
    assert payload["findings"][0]["check_id"] == "IAC_ACCESS_PUBLIC"


def test_fail_on_sets_exit_code(tmp_path):
    (tmp_path / "c.yaml").write_text("access_control:\n  public: true\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "high"])
    assert result.exit_code == 1


def test_fail_on_below_threshold_is_clean(tmp_path):
    (tmp_path / "c.yaml").write_text("access_control:\n  public: true\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "critical"])
    assert result.exit_code == 0


def test_scan_missing_path_errors(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path / "nope")])
    assert result.exit_code == 2


def test_clean_scan_reports_no_findings(tmp_path):
    (tmp_path / "c.yaml").write_text("access_control:\n  public: false\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "No findings" in result.stdout
