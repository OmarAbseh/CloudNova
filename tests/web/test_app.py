"""Web dashboard: routes render, scan works, bad input handled."""

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from cloudnova.web import create_app


@pytest.fixture
def client():
    return TestClient(create_app())


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_home_renders(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "CloudNova" in r.text


def test_scan_form(client):
    assert client.get("/scan").status_code == 200


def test_scan_runs_and_shows_grade(tmp_path, client):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" { acl = "public-read" }\n', encoding="utf-8"
    )
    r = client.post("/scan", data={"path": str(tmp_path)})
    assert r.status_code == 200
    assert "lower is better" in r.text  # posture score shown
    assert "public acl" in r.text.lower()  # the S3 public-ACL finding title


def test_scan_bad_path_shows_error(client):
    r = client.post("/scan", data={"path": "/definitely/not/here"})
    assert r.status_code == 200
    assert "not found" in r.text.lower()


def test_scan_escapes_html(tmp_path, client):
    # A path with HTML metacharacters must be escaped in the error message.
    r = client.post("/scan", data={"path": "<script>alert(1)</script>"})
    assert "<script>alert(1)</script>" not in r.text


def test_mentor_page(client):
    r = client.get("/mentor")
    assert r.status_code == 200
    assert "pentester" in r.text.lower()
    assert "Foundations" in r.text  # a curriculum module is listed


def test_mentor_page_shows_progress(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDNOVA_CONFIG_DIR", str(tmp_path))
    from cloudnova.range.mentor import mark_done

    mark_done("foundations")
    c = TestClient(create_app())
    r = c.get("/mentor")
    assert r.status_code == 200
    assert "Progress" in r.text
    assert "Next up" in r.text
    assert "1/12" in r.text


def test_mentor_toggle_marks_and_unmarks(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDNOVA_CONFIG_DIR", str(tmp_path))
    from cloudnova.range.mentor import completed

    c = TestClient(create_app())
    c.post("/mentor/toggle", data={"module_id": "foundations"}, follow_redirects=False)
    assert "foundations" in completed()
    c.post("/mentor/toggle", data={"module_id": "foundations"}, follow_redirects=False)
    assert "foundations" not in completed()


def test_mentor_toggle_unknown_id_is_safe(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDNOVA_CONFIG_DIR", str(tmp_path))
    c = TestClient(create_app())
    r = c.post("/mentor/toggle", data={"module_id": "nope"}, follow_redirects=False)
    assert r.status_code == 303


def test_scan_results_include_explain(tmp_path, client):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" { acl = "public-read" }\n', encoding="utf-8"
    )
    r = client.post("/scan", data={"path": str(tmp_path)})
    assert r.status_code == 200
    assert "Explain" in r.text  # per-finding expandable explanation
    assert "How to fix it:" in r.text


def test_security_headers_present(client):
    r = client.get("/")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in r.headers


def test_auth_required_when_password_set(monkeypatch):
    monkeypatch.setenv("CLOUDNOVA_WEB_PASSWORD", "s3cret")
    monkeypatch.setenv("CLOUDNOVA_WEB_USER", "omar")
    c = TestClient(create_app())
    # /health stays open for liveness probes
    assert c.get("/health").status_code == 200
    # protected route rejects missing/bad creds
    assert c.get("/").status_code == 401
    assert c.get("/", auth=("omar", "wrong")).status_code == 401
    # correct creds pass
    assert c.get("/", auth=("omar", "s3cret")).status_code == 200
