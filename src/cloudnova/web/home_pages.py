"""The signed-in home: what is my posture, and what should I do next.

Before this, a signed-in customer got the marketing hero, which is the wrong
use of the most valuable screen in the product. The characteristic question in
cloud security is not "what does this tool do", it is "how exposed am I right
now, and is that getting better or worse". So the page opens with the current
grade, the trend behind it, and what changed since the previous scan.

A brand new organization has none of that, and an empty dashboard is an
invitation to act rather than a blank page, so the same route renders a short
setup list keyed to real state instead.
"""

from __future__ import annotations

import html
from typing import Any

from cloudnova.platform.billing import Entitlements
from cloudnova.platform.tenancy import Org
from cloudnova.web.charts import TrendPoint, posture_trend_svg

_GRADE_COLOR = {"A": "#22c55e", "B": "#22c55e", "C": "#d97706", "D": "#f43f5e", "F": "#e11d48"}


def _e(v: object) -> str:
    return html.escape(str(v), quote=True)


def _when(stamp: str) -> str:
    return str(stamp or "")[:16].replace("T", " ")


def _target_name(scan: dict[str, Any]) -> str:
    raw = scan.get("targets")
    if isinstance(raw, dict) and raw.get("name"):
        return str(raw["name"])
    return "unknown target"


def _trend_points(scans: list[dict[str, Any]]) -> list[TrendPoint]:
    # list_scans is newest first; a trend reads left to right in time.
    points = []
    for scan in reversed(scans):
        score = scan.get("posture_score")
        if score is None:
            continue
        points.append(
            TrendPoint(
                label=_when(str(scan.get("started_at") or ""))[:10],
                score=int(score),
                grade=str(scan.get("grade") or "?"),
            )
        )
    return points[-15:]


def _delta_line(scans: list[dict[str, Any]]) -> str:
    """What changed since the previous scan, in one sentence.

    Direction matters more than the absolute number. A grade on its own does
    not tell anyone whether the work they did last week helped.
    """
    if len(scans) < 2:
        return (
            '<p class="muted" style="margin:0">Run another scan to start tracking '
            "whether this is improving.</p>"
        )
    now, before = scans[0], scans[1]
    a, b = now.get("findings_count"), before.get("findings_count")
    sa, sb = now.get("posture_score"), before.get("posture_score")
    if a is None or b is None or sa is None or sb is None:
        return ""
    d_find, d_score = int(a) - int(b), int(sa) - int(sb)
    if d_find == 0 and d_score == 0:
        return '<p style="margin:0">No change since the previous scan.</p>'
    if d_score < 0:
        word, cls = "improved", "ok"
    elif d_score > 0:
        word, cls = "got worse", ""
    else:
        word, cls = "changed", ""
    bits = []
    if d_find:
        bits.append(f"{abs(d_find)} {'more' if d_find > 0 else 'fewer'} finding(s)")
    if d_score:
        bits.append(f"score {'up' if d_score > 0 else 'down'} {abs(d_score)}")
    return (
        f'<p class="delta {cls}" style="margin:0">Posture {word} since the previous '
        f"scan: {', '.join(bits)}.</p>"
    )


def _setup_steps(
    *, org: Org, allowance: Entitlements | None, has_scan: bool, member_count: int
) -> str:
    """A setup list reflecting real state, so a finished step reads as finished."""
    steps = [
        (True, "Create an organization", f"You are {org.role} of {_e(org.name)}."),
        (
            has_scan,
            "Run your first scan",
            "Point it at a folder of infrastructure code. Try <code>examples</code> "
            "to see a real result immediately.",
        ),
        (
            member_count > 1,
            "Invite your team",
            "Scans and findings are shared with everyone in the organization.",
        ),
        (
            allowance is not None and allowance.plan.id != "free",
            "Choose a plan",
            "The free plan covers one person and twenty scans a month.",
        ),
    ]
    rows = []
    for done, title, detail in steps:
        mark = '<span class="step-done">done</span>' if done else '<span class="step-todo"></span>'
        rows.append(
            f'<li class="{"is-done" if done else ""}">{mark}'
            f"<div><b>{_e(title)}</b><br><span class='muted'>{detail}</span></div></li>"
        )
    return f'<ol class="steps">{"".join(rows)}</ol>'


def home_body(
    *,
    org: Org | None,
    scans: list[dict[str, Any]],
    allowance: Entitlements | None,
    member_count: int,
    error: str = "",
) -> str:
    """The signed-in overview, or the setup list when there is nothing yet."""
    if org is None:
        return _signed_out_marketing()

    banner = f'<p class="notice">{_e(error)}</p>' if error else ""

    if not scans:
        return f"""
        {banner}
        <h1 style="margin:6px 0 4px">Welcome to CloudNova</h1>
        <p class="muted" style="margin:0 0 18px;max-width:60ch">Four steps to a
          working security baseline. You have done the first one.</p>
        <div class="card">
          {_setup_steps(org=org, allowance=allowance, has_scan=False, member_count=member_count)}
          <p style="margin:18px 0 0"><a class="btn" href="/scan">Run a scan</a>
            <a class="btn ghost" href="/guide">Read the guide</a></p>
        </div>"""

    latest = scans[0]
    grade = str(latest.get("grade") or "?")
    score = latest.get("posture_score")
    colour = _GRADE_COLOR.get(grade, "#8b8b99")
    points = _trend_points(scans)
    chart = posture_trend_svg(points)

    recent = "".join(
        f'<tr><td class="muted">{_e(_when(str(s.get("started_at") or "")))}</td>'
        f"<td>{_e(_target_name(s))}</td>"
        f"<td>{_e(s.get('findings_count', 0))}</td>"
        f'<td><b style="color:{_GRADE_COLOR.get(str(s.get("grade")), "#8b8b99")}">'
        f"{_e(s.get('grade') or '-')}</b></td>"
        f'<td><a href="/history/{_e(s.get("id"))}">View</a></td></tr>'
        for s in scans[:5]
    )

    usage = ""
    if allowance is not None and not allowance.degraded:
        scans_left = allowance.scans_remaining
        usage = (
            f'<p class="muted" style="margin:14px 0 0;font-size:13px">'
            f"{allowance.plan.name} plan, "
            f"{allowance.usage.scans_this_month} scan(s) this month"
            + (f", {scans_left} remaining" if scans_left is not None else "")
            + ".</p>"
        )

    return f"""
    {banner}
    <div class="overview">
      <div class="card posture">
        <div class="grade" style="color:{colour}">{_e(grade)}</div>
        <div>
          <div style="font-size:15px;font-weight:700">{_e(score)} / 100 risk score</div>
          <p class="muted" style="margin:2px 0 0;font-size:13px">
            {_e(_target_name(latest))}, scanned {_e(_when(str(latest.get("started_at") or "")))}</p>
          {_delta_line(scans)}
        </div>
        <a class="btn" href="/scan">Run a scan</a>
      </div>
      {chart}
    </div>
    <div class="card" style="margin-top:16px">
      <div style="display:flex;justify-content:space-between;align-items:baseline">
        <h3 style="margin:0">Recent scans</h3>
        <a href="/history" style="font-size:13px">All history</a>
      </div>
      <table style="margin-top:8px"><thead><tr><th>When</th><th>Target</th>
      <th>Findings</th><th>Grade</th><th></th></tr></thead><tbody>{recent}</tbody></table>
      {usage}
    </div>"""


def _signed_out_marketing() -> str:
    """The landing hero, shown only when there is no organization to report on."""
    return """
    <section class="hero">
      <div>
        <h1>Find the <span class="accent">attack path</span><br>before they do.</h1>
        <p>Scan your cloud for misconfigurations, chain them into real attack paths,
           grade your posture, and train to break in, all in one tool.</p>
        <p style="margin-top:20px">
          <a class="btn" href="/scan">Run a scan</a>
          <a class="btn ghost" href="/guide">How it works</a>
        </p>
      </div>
      <div class="hero-3d"><canvas id="hero3d"></canvas><div class="orb"></div></div>
    </section>

    <div class="grid">
      <div class="card"><h3>30+ checks, 5 formats</h3>
        <p>Terraform, CloudFormation, Kubernetes, CloudTrail and logs, mapped to CIS
           and MITRE ATT&amp;CK.</p></div>
      <div class="card"><h3>Attack paths</h3>
        <p>Exposed compute, over-privileged role, sensitive data, chained
           automatically.</p></div>
      <div class="card"><h3>Author and audit IAM</h3>
        <p>Generate least-privilege policies and catch privilege-escalation
           vectors.</p></div>
      <div class="card"><h3>Learn to hack</h3>
        <p>An authorization-first pentest toolkit and a tutor that takes you to
           job-ready.</p></div>
    </div>"""
