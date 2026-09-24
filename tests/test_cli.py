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


def test_baseline_command_and_filter(tmp_path):
    (tmp_path / "c.yaml").write_text("access_control:\n  public: true\n", encoding="utf-8")
    bl = tmp_path / "bl.json"
    created = runner.invoke(app, ["baseline", str(tmp_path), "-o", str(bl)])
    assert created.exit_code == 0
    assert bl.exists()
    # With the baseline applied, a re-scan reports nothing and the gate passes.
    scanned = runner.invoke(app, ["scan", str(tmp_path), "--baseline", str(bl), "--fail-on", "low"])
    assert scanned.exit_code == 0


def test_scan_sarif_format(tmp_path):
    (tmp_path / "c.yaml").write_text("access_control:\n  public: true\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "sarif"])
    assert result.exit_code == 0
    assert '"version": "2.1.0"' in result.stdout


def test_scan_min_severity_filters(tmp_path):
    # public access is HIGH, missing timeout is LOW; --min-severity high drops the LOW one.
    (tmp_path / "c.yaml").write_text(
        "access_control:\n  public: true\nsession:\n  timeout: 0\n", encoding="utf-8"
    )
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--format", "json", "--min-severity", "high"]
    )
    assert result.exit_code == 0
    import json

    ids = {f["check_id"] for f in json.loads(result.stdout)["findings"]}
    assert "IAC_ACCESS_PUBLIC" in ids
    assert "IAC_SESSION_NO_TIMEOUT" not in ids


def test_scan_no_graph_flag(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" { acl = "public-read" }\n', encoding="utf-8"
    )
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-graph"])
    assert result.exit_code == 0


def test_scan_html_format(tmp_path):
    (tmp_path / "c.yaml").write_text("access_control:\n  public: true\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "html"])
    assert result.exit_code == 0
    assert "<!doctype html>" in result.stdout


def test_scan_unknown_format_errors(tmp_path):
    (tmp_path / "c.yaml").write_text("access_control:\n  public: false\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "xml"])
    assert result.exit_code == 2
