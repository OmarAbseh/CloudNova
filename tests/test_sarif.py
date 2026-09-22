"""SARIF output must be valid 2.1.0 that GitHub code-scanning accepts."""

import json

from cloudnova.core.engine import Engine
from cloudnova.reporting import render_sarif


def _scan(tmp_path, body, name="c.yaml"):
    (tmp_path / name).write_text(body, encoding="utf-8")
    return Engine().scan_path(tmp_path)


def test_sarif_shape(tmp_path):
    result = _scan(tmp_path, "access_control:\n  public: true\n")
    doc = json.loads(render_sarif(result))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "CloudNova"
    assert run["results"], "expected at least one result"


def test_sarif_levels_and_security_severity(tmp_path):
    result = _scan(tmp_path, "access_control:\n  public: true\n")
    run = json.loads(render_sarif(result))["runs"][0]
    result0 = run["results"][0]
    assert result0["level"] in {"error", "warning", "note"}
    rule0 = run["tool"]["driver"]["rules"][0]
    # GitHub requires a numeric security-severity string.
    sev = float(rule0["properties"]["security-severity"])
    assert 0.0 <= sev <= 10.0


def test_sarif_empty_scan_is_valid(tmp_path):
    result = _scan(tmp_path, "access_control:\n  public: false\n")
    doc = json.loads(render_sarif(result))
    assert doc["runs"][0]["results"] == []


def test_sarif_rule_dedup(tmp_path):
    # Two buckets that trip the same rule -> two results but ONE rule entry.
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "a" { acl = "public-read" }\n'
        'resource "aws_s3_bucket" "b" { acl = "public-read" }\n',
        encoding="utf-8",
    )
    run = json.loads(render_sarif(Engine().scan_path(tmp_path)))["runs"][0]
    acl_results = [r for r in run["results"] if r["ruleId"] == "TF_S3_PUBLIC_ACL"]
    acl_rules = [r for r in run["tool"]["driver"]["rules"] if r["id"] == "TF_S3_PUBLIC_ACL"]
    assert len(acl_results) == 2
    assert len(acl_rules) == 1
