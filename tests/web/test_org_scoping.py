"""Per-org scoping: scans persist into the caller's org, and only theirs.

The isolation itself is enforced by RLS and proven against the live database
in the migration. What these tests pin down is the layer above it: that the
dashboard always sends the user's own token, always stamps the org it claims
to, and cannot be steered into another tenant by a tampered cookie.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
import httpx

from cloudnova.web.auth import ORG_COOKIE

SESSION = {
    "access_token": "user-jwt",
    "refresh_token": "refresh-xyz",
    "expires_in": 3600,
    "user": {"id": "user-1", "email": "omar@example.test"},
}
USER = {"id": "user-1", "email": "omar@example.test"}

ACME = {"role": "owner", "organizations": {"id": "org-acme", "name": "Acme"}}
GLOBEX = {"role": "member", "organizations": {"id": "org-globex", "name": "Globex"}}


def _supabase(memberships, *, on_rest=None):
    """A Supabase fake with a fixed membership list."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/auth/v1/token":
            return httpx.Response(200, json=SESSION)
        if path == "/auth/v1/user":
            token = request.headers["Authorization"].removeprefix("Bearer ")
            if token == "user-jwt":
                return httpx.Response(200, json=USER)
            return httpx.Response(401, json={"msg": "bad"})
        if path == "/rest/v1/memberships":
            return httpx.Response(200, json=memberships)
        if on_rest is not None:
            custom = on_rest(request)
            if custom is not None:
                return custom
        if path == "/rest/v1/targets":
            return httpx.Response(200, json=[{"id": "target-1"}])
        if path == "/rest/v1/scans":
            if request.method == "POST":
                return httpx.Response(201, json=[{"id": "scan-1"}])
            return httpx.Response(200, json=[])
        if path == "/rest/v1/findings":
            return httpx.Response(201, json=[])
        if path.startswith("/rest/v1/"):
            return httpx.Response(200, json=[])
        return httpx.Response(404, json={"msg": f"unexpected {path}"})

    return handler


def _signed_in(platform_app, memberships, *, on_rest=None):
    app, seen = platform_app(_supabase(memberships, on_rest=on_rest))
    app.post(
        "/login",
        data={"email": "omar@example.test", "password": "pw"},
        follow_redirects=False,
    )
    seen.clear()
    return app, seen


def _posts_to(seen, path):
    return [r for r in seen if r.url.path == path and r.method == "POST"]


def _tf(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" { acl = "public-read" }\n', encoding="utf-8"
    )
    return str(tmp_path)


# -- persistence -----------------------------------------------------------


def test_scan_is_saved_against_the_current_org(platform_app, tmp_path):
    app, seen = _signed_in(platform_app, [ACME])
    r = app.post("/scan", data={"path": _tf(tmp_path)})
    assert r.status_code == 200

    scans = _posts_to(seen, "/rest/v1/scans")
    assert len(scans) == 1
    body = json.loads(scans[0].content)[0]
    assert body["org_id"] == "org-acme"
    assert body["created_by"] == "user-1"
    assert body["findings_count"] >= 1


def test_findings_are_saved_stamped_with_the_same_org(platform_app, tmp_path):
    app, seen = _signed_in(platform_app, [ACME])
    app.post("/scan", data={"path": _tf(tmp_path)})

    writes = _posts_to(seen, "/rest/v1/findings")
    assert writes, "findings were never written"
    rows = json.loads(writes[0].content)
    assert rows
    assert {row["org_id"] for row in rows} == {"org-acme"}
    assert {row["scan_id"] for row in rows} == {"scan-1"}


def test_every_write_is_signed_with_the_users_own_token(platform_app, tmp_path):
    # This is what makes RLS the enforcement point rather than decoration.
    app, seen = _signed_in(platform_app, [ACME])
    app.post("/scan", data={"path": _tf(tmp_path)})
    rest = [r for r in seen if r.url.path.startswith("/rest/v1/")]
    assert rest
    for request in rest:
        assert request.headers["Authorization"] == "Bearer user-jwt"


def test_scan_results_still_render_when_saving_fails(platform_app, tmp_path):
    # The scan succeeded; losing its output because we could not file it
    # would be the worse failure.
    def on_rest(request):
        if request.url.path == "/rest/v1/scans" and request.method == "POST":
            return httpx.Response(403, json={"message": "row-level security"})
        return None

    app, _ = _signed_in(platform_app, [ACME], on_rest=on_rest)
    r = app.post("/scan", data={"path": _tf(tmp_path)})
    assert r.status_code == 200
    assert "public acl" in r.text.lower()  # the finding is still shown
    assert "saving it failed" in r.text.lower()
    assert "row-level security" in r.text


def test_confirmation_links_to_the_saved_scan(platform_app, tmp_path):
    app, _ = _signed_in(platform_app, [ACME])
    r = app.post("/scan", data={"path": _tf(tmp_path)})
    assert "/history/scan-1" in r.text
    assert "Acme" in r.text


def test_local_mode_persists_nothing(client, tmp_path):
    # No platform configured: the scanner still works, nothing is stored.
    r = client.post("/scan", data={"path": _tf(tmp_path)})
    assert r.status_code == 200
    assert "public acl" in r.text.lower()
    assert "Saved to" not in r.text


# -- reading back ----------------------------------------------------------


def test_history_lists_only_the_current_orgs_scans(platform_app):
    captured = {}

    def on_rest(request):
        if request.url.path == "/rest/v1/scans" and request.method == "GET":
            captured["params"] = dict(request.url.params)
            return httpx.Response(200, json=[])
        return None

    app, _ = _signed_in(platform_app, [ACME], on_rest=on_rest)
    assert app.get("/history").status_code == 200
    assert captured["params"]["org_id"] == "eq.org-acme"


def test_history_renders_saved_scans(platform_app):
    def on_rest(request):
        if request.url.path == "/rest/v1/scans" and request.method == "GET":
            return httpx.Response(
                200,
                json=[
                    {
                        "id": "scan-1",
                        "started_at": "2026-09-30T10:00:00+00:00",
                        "findings_count": 3,
                        "posture_score": 60,
                        "grade": "D",
                        "targets": {"name": "./infra", "kind": "iac"},
                    }
                ],
            )
        return None

    app, _ = _signed_in(platform_app, [ACME], on_rest=on_rest)
    r = app.get("/history")
    assert "./infra" in r.text
    assert "/history/scan-1" in r.text
    assert "2026-09-30 10:00:00" in r.text


def test_scan_detail_reads_findings_for_that_scan(platform_app):
    captured = {}

    def on_rest(request):
        if request.url.path == "/rest/v1/findings" and request.method == "GET":
            captured["params"] = dict(request.url.params)
            return httpx.Response(
                200,
                json=[
                    {
                        "severity": "critical",
                        "title": "Public bucket",
                        "description": "d",
                        "remediation": "r",
                        "location_path": "main.tf",
                        "location_resource": "aws_s3_bucket.b",
                    }
                ],
            )
        return None

    app, _ = _signed_in(platform_app, [ACME], on_rest=on_rest)
    r = app.get("/history/scan-1")
    assert captured["params"]["scan_id"] == "eq.scan-1"
    assert "Public bucket" in r.text
    assert "aws_s3_bucket.b" in r.text


def test_a_scan_from_another_tenant_simply_shows_nothing(platform_app):
    # RLS returns an empty set rather than an error, so the page must render
    # an honest empty state instead of leaking that the id exists.
    app, _ = _signed_in(platform_app, [ACME])
    r = app.get("/history/someone-elses-scan")
    assert r.status_code == 200
    assert "No findings recorded" in r.text


def test_history_survives_a_supabase_error(platform_app):
    def on_rest(request):
        if request.url.path == "/rest/v1/scans" and request.method == "GET":
            return httpx.Response(500, json={"message": "database is on fire"})
        return None

    app, _ = _signed_in(platform_app, [ACME], on_rest=on_rest)
    r = app.get("/history")
    assert r.status_code == 200
    assert "database is on fire" in r.text


# -- org selection ---------------------------------------------------------


def test_single_org_shows_its_name_not_a_picker(platform_app):
    app, _ = _signed_in(platform_app, [ACME])
    r = app.get("/history")
    assert "Acme" in r.text
    assert "<select" not in r.text  # the class name alone lives in the CSS


def test_multiple_orgs_offer_a_switcher(platform_app):
    app, _ = _signed_in(platform_app, [ACME, GLOBEX])
    r = app.get("/history")
    assert "<select" in r.text
    assert 'value="org-globex"' in r.text
    assert "Globex" in r.text


def test_switching_org_changes_what_history_queries(platform_app):
    captured = []

    def on_rest(request):
        if request.url.path == "/rest/v1/scans" and request.method == "GET":
            captured.append(dict(request.url.params)["org_id"])
            return httpx.Response(200, json=[])
        return None

    app, _ = _signed_in(platform_app, [ACME, GLOBEX], on_rest=on_rest)
    app.get("/history")
    app.post("/orgs/switch", data={"org_id": "org-globex"}, follow_redirects=False)
    app.get("/history")
    assert captured == ["eq.org-acme", "eq.org-globex"]


def test_cookie_naming_an_org_you_are_not_in_is_ignored(platform_app):
    # The cookie only ever selects from orgs the database returned for this
    # user, so tampering falls back rather than reaching another tenant.
    captured = []

    def on_rest(request):
        if request.url.path == "/rest/v1/scans" and request.method == "GET":
            captured.append(dict(request.url.params)["org_id"])
            return httpx.Response(200, json=[])
        return None

    app, _ = _signed_in(platform_app, [ACME], on_rest=on_rest)
    app.cookies.set(ORG_COOKIE, "org-someone-else")
    app.get("/history")
    assert captured == ["eq.org-acme"]


def test_switch_refuses_an_org_you_are_not_a_member_of(platform_app):
    app, _ = _signed_in(platform_app, [ACME])
    r = app.post("/orgs/switch", data={"org_id": "org-globex"}, follow_redirects=False)
    # No cookie is set, so the next request stays on Acme.
    assert "cn_org" not in r.headers.get("set-cookie", "")


def test_scan_saves_into_the_org_you_switched_to(platform_app, tmp_path):
    app, seen = _signed_in(platform_app, [ACME, GLOBEX])
    app.post("/orgs/switch", data={"org_id": "org-globex"})
    seen.clear()
    app.post("/scan", data={"path": _tf(tmp_path)})
    body = json.loads(_posts_to(seen, "/rest/v1/scans")[0].content)[0]
    assert body["org_id"] == "org-globex"
