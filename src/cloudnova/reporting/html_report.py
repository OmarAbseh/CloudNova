"""Self-contained HTML report formatter.

Produces a single shareable ``.html`` file — no external CSS/JS/fonts — with the
posture score, a severity summary, and every finding. Useful for attaching to a
ticket, emailing a team, or showing off a scan. All styling is inline so the
file works offline and can't leak data to a CDN.
"""

from __future__ import annotations

import html
from datetime import UTC, datetime

from cloudnova.core.engine import ScanResult
from cloudnova.core.findings import Finding, Severity
from cloudnova.scoring import posture_score

_SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "#b3123b",
    Severity.HIGH: "#d1453b",
    Severity.MEDIUM: "#c77700",
    Severity.LOW: "#1f7a8c",
    Severity.INFO: "#6b7280",
}
_GRADE_COLOR = {"A": "#1a7f37", "B": "#1a7f37", "C": "#c77700", "D": "#d1453b", "F": "#b3123b"}


def _e(text: object) -> str:
    """HTML-escape any value so finding content can't inject markup."""
    return html.escape(str(text), quote=True)


def _finding_card(f: Finding) -> str:
    color = _SEVERITY_COLOR[f.severity]
    tags = "".join(
        f'<span class="tag">{_e(t)}</span>' for t in ([*f.cis_controls, *f.mitre_attack])
    )
    loc = _e(f.location.path)
    if f.location.resource:
        loc += f" · {_e(f.location.resource)}"
    return f"""
    <div class="card" style="border-left-color:{color}">
      <div class="card-head">
        <span class="sev" style="background:{color}">{_e(f.severity.value.upper())}</span>
        <span class="cid">{_e(f.check_id)}</span>
        <span class="conf">confidence: {_e(f.confidence.value)}</span>
      </div>
      <h3>{_e(f.title)}</h3>
      <p class="loc">{loc}</p>
      <p>{_e(f.description)}</p>
      <p class="fix"><strong>Fix:</strong> {_e(f.remediation)}</p>
      <div class="tags">{tags}</div>
    </div>"""


def render_html(result: ScanResult, *, title: str = "CloudNova Security Report") -> str:
    score = posture_score(result)
    grade_color = _GRADE_COLOR[score.grade]
    findings = result.sorted_findings()

    counts = dict.fromkeys(Severity, 0)
    for f in result.findings:
        counts[f.severity] += 1
    pills = "".join(
        f'<span class="pill" style="background:{_SEVERITY_COLOR[s]}">{s.value}: {counts[s]}</span>'
        for s in Severity
        if counts[s]
    )
    cards = "\n".join(_finding_card(f) for f in findings) or '<p class="empty">No findings. 🎉</p>'
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 15px/1.5 system-ui, sans-serif; margin: 0; background: #f7f7f8; color: #111; }}
  .wrap {{ max-width: 900px; margin: 0 auto; padding: 32px 20px; }}
  header {{ display: flex; align-items: center; gap: 24px; flex-wrap: wrap;
           border-bottom: 1px solid #ddd; padding-bottom: 20px; margin-bottom: 24px; }}
  h1 {{ font-size: 22px; margin: 0; }}
  .grade {{ font-size: 44px; font-weight: 800; color: {grade_color}; line-height: 1; }}
  .score {{ color: #555; font-size: 13px; }}
  .pills, .tags {{ display: flex; gap: 8px; flex-wrap: wrap; }}
  .pill {{ color: #fff; padding: 3px 10px; border-radius: 999px;
          font-size: 12px; font-weight: 600; }}
  .card {{ background: #fff; border: 1px solid #e5e5e5; border-left-width: 5px;
          border-radius: 8px; padding: 16px 18px; margin: 14px 0; }}
  .card-head {{ display: flex; align-items: center; gap: 10px; font-size: 12px; }}
  .sev {{ color: #fff; padding: 2px 8px; border-radius: 4px; font-weight: 700; }}
  .cid {{ font-family: ui-monospace, monospace; color: #444; }}
  .conf {{ margin-left: auto; color: #777; }}
  .card h3 {{ margin: 10px 0 4px; font-size: 16px; }}
  .loc {{ font-family: ui-monospace, monospace; font-size: 12px; color: #666; margin: 0 0 8px; }}
  .fix {{ color: #1a7f37; }}
  .tag {{ background: #eef; color: #334; padding: 2px 8px; border-radius: 4px; font-size: 11px; }}
  .empty {{ font-size: 18px; color: #1a7f37; }}
  footer {{ margin-top: 28px; color: #888; font-size: 12px; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #16171a; color: #e8e8ea; }}
    .card {{ background: #1f2024; border-color: #333; }}
    .cid, .loc {{ color: #aaa; }}
    header {{ border-color: #333; }}
    .tag {{ background: #2a2b31; color: #ccd; }}
  }}
</style>
</head>
<body>
  <div class="wrap">
    <header>
      <div>
        <div class="grade">{_e(score.grade)}</div>
        <div class="score">{score.score}/100 · lower is better</div>
      </div>
      <div>
        <h1>{_e(title)}</h1>
        <p style="margin:6px 0; color:#666;">
          {result.files_scanned} file(s) · {result.checks_run} check(s) ·
          {len(findings)} finding(s)
        </p>
        <div class="pills">{pills}</div>
      </div>
    </header>
    {cards}
    <footer>Generated by CloudNova on {generated}.</footer>
  </div>
</body>
</html>"""
