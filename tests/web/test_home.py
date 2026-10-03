"""The signed-in overview and the setup list that replaces it when empty."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from cloudnova.platform.billing import FREE_PLAN, Entitlements, Usage
from cloudnova.platform.tenancy import Org
from cloudnova.web.charts import TrendPoint, posture_trend_svg
from cloudnova.web.home_pages import home_body

ORG = Org(id="org-1", name="Acme", role="owner")


def _scan(score, grade, findings, when="2026-10-01T10:00:00Z", sid="s1"):
    return {
        "id": sid,
        "started_at": when,
        "posture_score": score,
        "grade": grade,
        "findings_count": findings,
        "targets": {"name": "./infra", "kind": "iac"},
    }


def _ent(plan=FREE_PLAN, scans=1):
    return Entitlements(plan=plan, usage=Usage(1, 0, scans), status="none")


# -- empty state -----------------------------------------------------------


def test_a_new_org_gets_a_setup_list_not_an_empty_dashboard(make_client=None):
    body = home_body(org=ORG, scans=[], allowance=_ent(), member_count=1)
    assert "Welcome to CloudNova" in body
    assert "Run your first scan" in body
    assert "Run a scan" in body
    # The step already satisfied reads as satisfied.
    assert "Create an organization" in body
    assert body.count("step-done") == 1


def test_setup_list_marks_steps_done_as_state_changes():
    full = Entitlements(plan=FREE_PLAN, usage=Usage(3, 0, 2), status="active")
    body = home_body(org=ORG, scans=[], allowance=full, member_count=3)
    # org created and team invited are both done now
    assert body.count("step-done") == 2


def test_empty_state_points_at_the_guide():
    body = home_body(org=ORG, scans=[], allowance=_ent(), member_count=1)
    assert 'href="/guide"' in body


# -- overview --------------------------------------------------------------


def test_overview_leads_with_the_current_grade():
    body = home_body(org=ORG, scans=[_scan(60, "D", 12)], allowance=_ent(), member_count=1)
    assert "60 / 100 risk score" in body
    assert ">D<" in body
    assert "./infra" in body


def test_one_scan_is_not_presented_as_a_trend():
    # Drawing an axis around a single dot overstates what is known.
    body = home_body(org=ORG, scans=[_scan(60, "D", 12)], allowance=_ent(), member_count=1)
    assert "<svg" not in body
    assert "Run another scan to start tracking" in body


def test_two_scans_produce_a_chart_and_a_direction():
    scans = [_scan(40, "C", 8, "2026-10-02T10:00:00Z", "s2"), _scan(60, "D", 12)]
    body = home_body(org=ORG, scans=scans, allowance=_ent(), member_count=1)
    assert "<svg" in body
    assert "improved" in body
    assert "score down 20" in body
    assert "4 fewer finding(s)" in body


def test_a_worse_posture_says_so():
    scans = [_scan(80, "F", 20, "2026-10-02T10:00:00Z", "s2"), _scan(60, "D", 12)]
    body = home_body(org=ORG, scans=scans, allowance=_ent(), member_count=1)
    assert "got worse" in body
    assert "8 more finding(s)" in body


def test_no_change_is_stated_plainly():
    scans = [_scan(60, "D", 12, "2026-10-02T10:00:00Z", "s2"), _scan(60, "D", 12)]
    body = home_body(org=ORG, scans=scans, allowance=_ent(), member_count=1)
    assert "No change since the previous scan" in body


def test_overview_lists_recent_scans_and_links_to_each():
    scans = [_scan(40, "C", 8, "2026-10-02T10:00:00Z", "s2"), _scan(60, "D", 12, sid="s1")]
    body = home_body(org=ORG, scans=scans, allowance=_ent(), member_count=1)
    assert "/history/s2" in body and "/history/s1" in body
    assert 'href="/history"' in body


def test_overview_shows_plan_usage():
    body = home_body(org=ORG, scans=[_scan(60, "D", 12)], allowance=_ent(scans=5), member_count=1)
    assert "Free plan" in body
    assert "5 scan(s) this month" in body
    assert "15 remaining" in body


def test_a_billing_outage_hides_usage_rather_than_showing_zeros():
    degraded = Entitlements(
        plan=FREE_PLAN, usage=Usage(0, 0, 0), status="unknown", degraded=True, error="down"
    )
    body = home_body(org=ORG, scans=[_scan(60, "D", 12)], allowance=degraded, member_count=1)
    assert "scan(s) this month" not in body


def test_no_org_falls_back_to_the_marketing_hero():
    body = home_body(org=None, scans=[], allowance=None, member_count=0)
    assert "attack path" in body
    assert "hero" in body


def test_a_read_error_is_surfaced_not_swallowed():
    body = home_body(org=ORG, scans=[], allowance=None, member_count=0, error="database is down")
    assert "database is down" in body


# -- the chart -------------------------------------------------------------


def test_chart_needs_two_points():
    assert posture_trend_svg([]) == ""
    assert posture_trend_svg([TrendPoint("2026-10-01", 50, "C")]) == ""


def test_chart_is_self_contained_and_labelled():
    pts = [TrendPoint("2026-10-01", 80, "F"), TrendPoint("2026-10-02", 20, "B")]
    svg = posture_trend_svg(pts)
    # Strict CSP blocks every external asset, so nothing may be referenced out.
    assert "http" not in svg
    assert "<script" not in svg
    assert 'role="img"' in svg and "aria-label" in svg
    # Single series needs no legend; the caption names it.
    assert "Higher is worse" in svg
    # Hover text without JavaScript.
    assert svg.count("<title>") == 2
    assert "grade F" in svg and "grade B" in svg


def test_chart_labels_only_the_ends():
    pts = [TrendPoint(f"2026-10-0{i}", 10 * i, "C") for i in range(1, 6)]
    svg = posture_trend_svg(pts)
    assert svg.count("<circle") == 5
    # The latest value is labelled; the intermediate ones are not.
    assert ">50<" in svg
    assert ">30<" not in svg


def test_chart_clamps_scores_into_range():
    # A malformed score must not push the path outside the viewBox.
    svg = posture_trend_svg([TrendPoint("a", -10, "A"), TrendPoint("b", 500, "F")])
    for coord in svg.split('points="')[2].split('"')[0].split():
        _, y = coord.split(",")
        assert 0 <= float(y) <= 170


def test_chart_escapes_labels():
    svg = posture_trend_svg([TrendPoint("<script>x</script>", 10, "A"), TrendPoint("b", 20, "B")])
    assert "<script>" not in svg
