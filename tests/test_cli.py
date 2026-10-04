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


def test_iam_generate_and_analyze_roundtrip(tmp_path):
    spec = tmp_path / "grants.yaml"
    spec.write_text(
        "grants:\n  - service: s3\n    access: [read]\n    resources: ['arn:aws:s3:::b/*']\n",
        encoding="utf-8",
    )
    out = tmp_path / "policy.json"
    gen = runner.invoke(app, ["iam", "generate", str(spec), "-o", str(out)])
    assert gen.exit_code == 0
    assert out.exists()
    # The generated policy analyzes clean.
    analyzed = runner.invoke(app, ["iam", "analyze", str(out)])
    assert analyzed.exit_code == 0
    assert "No findings" in analyzed.stdout


def test_iam_analyze_flags_bad_policy(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text('{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}', encoding="utf-8")
    result = runner.invoke(app, ["iam", "analyze", str(p), "--format", "json"])
    assert result.exit_code == 0
    import json

    ids = {f["check_id"] for f in json.loads(result.stdout)["findings"]}
    assert "IAM_FULL_WILDCARD" in ids


def test_iam_generate_invalid_spec_errors(tmp_path):
    spec = tmp_path / "bad.yaml"
    spec.write_text(
        "grants:\n  - service: s3\n    access: read\n    resources: ['*']\n", encoding="utf-8"
    )
    result = runner.invoke(app, ["iam", "generate", str(spec)])
    assert result.exit_code == 2


def test_range_check_allow_and_deny(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "authorization:\n  program: P\n  authorized_by: policy\n  acknowledged: true\n"
        "in_scope:\n  - '*.example.com'\nout_of_scope:\n  - admin.example.com\n",
        encoding="utf-8",
    )
    ok = runner.invoke(app, ["range", "check", "api.example.com", "--scope", str(scope)])
    assert ok.exit_code == 0 and "ALLOW" in ok.stdout
    denied = runner.invoke(app, ["range", "check", "evil.com", "--scope", str(scope)])
    assert denied.exit_code == 1 and "DENY" in denied.stdout
    excluded = runner.invoke(app, ["range", "check", "admin.example.com", "--scope", str(scope)])
    assert excluded.exit_code == 1


def test_range_scope_show(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "authorization:\n  program: MyProgram\n  authorized_by: policy\n  acknowledged: true\n"
        "in_scope:\n  - '*.example.com'\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["range", "scope", str(scope)])
    assert result.exit_code == 0
    assert "MyProgram" in result.stdout


def test_mentor_path_and_topic():
    p = runner.invoke(app, ["range", "mentor", "path"])
    assert p.exit_code == 0 and "Foundations" in p.stdout
    t = runner.invoke(app, ["range", "mentor", "topic", "burp-suite"])
    assert t.exit_code == 0 and "Repeater" in t.stdout


def test_mentor_cert_track():
    r = runner.invoke(app, ["range", "mentor", "cert", "OSCP"])
    assert r.exit_code == 0 and "OSCP" in r.stdout


def test_mentor_unknown_topic_errors():
    r = runner.invoke(app, ["range", "mentor", "topic", "nope"])
    assert r.exit_code == 2


def test_mentor_lab_gated(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "authorization:\n  program: P\n  authorized_by: policy\n  acknowledged: true\n"
        "in_scope:\n  - '*.example.com'\n",
        encoding="utf-8",
    )
    ok = runner.invoke(app, ["range", "mentor", "lab", "box.example.com", "--scope", str(scope)])
    assert ok.exit_code == 0 and "guided lab plan" in ok.stdout
    denied = runner.invoke(app, ["range", "mentor", "lab", "evil.com", "--scope", str(scope)])
    assert denied.exit_code == 1


def test_range_report_generation(tmp_path):
    eng = tmp_path / "engagement.yaml"
    eng.write_text(
        "engagement:\n  client: Acme\n  tester: me\n  scope: '*.acme.com'\n"
        "findings:\n  - title: SQLi\n    severity: critical\n    affected: /login\n"
        "    description: d\n    remediation: use params\n",
        encoding="utf-8",
    )
    out = tmp_path / "report.md"
    r = runner.invoke(app, ["range", "report", str(eng), "-o", str(out)])
    assert r.exit_code == 0
    assert out.exists()
    text = out.read_text()
    assert "Penetration Test Report - Acme" in text
    assert "SQLi" in text


def test_range_recon_scoped(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "authorization:\n  program: P\n  authorized_by: policy\n  acknowledged: true\n"
        "in_scope:\n  - 10.0.0.0/8\n",
        encoding="utf-8",
    )
    xml = tmp_path / "nmap.xml"
    xml.write_text(
        '<?xml version="1.0"?><nmaprun>'
        '<host><address addr="10.1.2.3" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>'
        "</ports></host>"
        '<host><address addr="1.2.3.4" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>'
        "</ports></host></nmaprun>",
        encoding="utf-8",
    )
    r = runner.invoke(app, ["range", "recon", str(xml), "--scope", str(scope)])
    assert r.exit_code == 0
    assert "10.1.2.3" in r.stdout
    assert "skipped (out of scope): 1.2.3.4" in r.stdout


def test_mentor_ask_offline(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    r = runner.invoke(app, ["range", "mentor", "ask", "how do I use burp suite?"])
    assert r.exit_code == 0
    assert "Burp Suite" in r.stdout


def test_range_persona_switch(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDNOVA_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("CLOUDNOVA_PERSONA", raising=False)
    assert runner.invoke(app, ["range", "persona", "use", "gh0st"]).exit_code == 0
    who = runner.invoke(app, ["range", "whoami"])
    assert who.exit_code == 0 and "gh0st" in who.stdout


def test_range_report_uses_persona_byline(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDNOVA_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("CLOUDNOVA_PERSONA", "gh0st")
    eng = tmp_path / "e.yaml"
    eng.write_text(
        "engagement:\n  client: Acme\n  scope: '*.acme.com'\n"
        "findings:\n  - title: X\n    severity: low\n    affected: a\n"
        "    description: d\n    remediation: r\n",
        encoding="utf-8",
    )
    out = tmp_path / "r.md"
    r = runner.invoke(app, ["range", "report", str(eng), "-o", str(out)])
    assert r.exit_code == 0
    assert "gh0st" in out.read_text()  # byline defaulted to the active persona


def test_triage_command_offline(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    (tmp_path / "c.yaml").write_text("access_control:\n  public: true\n", encoding="utf-8")
    r = runner.invoke(app, ["triage", str(tmp_path)])
    assert r.exit_code == 0
    assert "What it is:" in r.stdout


def test_triage_clean_scan(tmp_path):
    (tmp_path / "c.yaml").write_text("access_control:\n  public: false\n", encoding="utf-8")
    r = runner.invoke(app, ["triage", str(tmp_path)])
    assert r.exit_code == 0
    assert "No findings" in r.stdout


def test_diff_command(tmp_path):
    import json as _json

    # First scan -> save JSON with only the public-access finding.
    cfg = tmp_path / "c.yaml"
    cfg.write_text("access_control:\n  public: true\n", encoding="utf-8")
    first = runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--no-graph"])
    old = tmp_path / "old.json"
    old.write_text(first.stdout, encoding="utf-8")
    _json.loads(old.read_text())  # valid JSON

    # Introduce a second issue, then diff.
    cfg.write_text(
        "access_control:\n  public: true\nauthentication:\n  password_required: false\n",
        encoding="utf-8",
    )
    r = runner.invoke(app, ["diff", str(old), str(tmp_path), "--fail-on-new"])
    assert r.exit_code == 1  # a new finding was introduced
    assert "Introduced" in r.stdout
    assert "IAC_AUTH_NO_PASSWORD" in r.stdout or "Password" in r.stdout


def test_mentor_progress_flow(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDNOVA_CONFIG_DIR", str(tmp_path))
    assert runner.invoke(app, ["range", "mentor", "done", "foundations"]).exit_code == 0
    prog = runner.invoke(app, ["range", "mentor", "progress"])
    assert prog.exit_code == 0 and "1/12" in prog.stdout
    nxt = runner.invoke(app, ["range", "mentor", "next"])
    assert nxt.exit_code == 0


def test_mentor_done_unknown(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDNOVA_CONFIG_DIR", str(tmp_path))
    assert runner.invoke(app, ["range", "mentor", "done", "nope"]).exit_code == 2


def test_mentor_undone(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDNOVA_CONFIG_DIR", str(tmp_path))
    runner.invoke(app, ["range", "mentor", "done", "foundations"])
    r = runner.invoke(app, ["range", "mentor", "undone", "foundations"])
    assert r.exit_code == 0 and "0/12" in r.stdout


def test_report_command_writes_a_client_report(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n', encoding="utf-8"
    )
    out = tmp_path / "report.html"
    res = runner.invoke(
        app,
        [
            "report",
            str(tmp_path),
            "--client",
            "Acme GmbH",
            "--scope",
            "terraform/ at commit abc123",
            "--assessor",
            "O. Abseh",
            "-o",
            str(out),
        ],
    )
    assert res.exit_code == 0, res.output
    page = out.read_text(encoding="utf-8")
    assert "Acme GmbH" in page
    assert "terraform/ at commit abc123" in page
    assert "Confidential" in page


def test_report_command_defaults_the_scope_but_says_so(tmp_path):
    # An unstated scope is the first thing a dispute turns on, so the default
    # is explicit rather than silent.
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n', encoding="utf-8")
    out = tmp_path / "r.html"
    res = runner.invoke(app, ["report", str(tmp_path), "--client", "X", "-o", str(out)])
    assert res.exit_code == 0
    assert "Infrastructure-as-code under" in out.read_text(encoding="utf-8")


def test_report_command_rejects_a_missing_path(tmp_path):
    res = runner.invoke(
        app, ["report", "/definitely/not/here", "--client", "X", "-o", str(tmp_path / "r.html")]
    )
    assert res.exit_code == 2
    assert "not found" in res.output.lower()
