"""The FastAPI application: a local dashboard for CloudNova.

Server-rendered HTML (no JS build step), reusing the tested ``service`` and
``range`` layers. Routes:

- ``/``            overview + operator persona
- ``/scan``        run a scan on a path and view findings / score / attack paths
- ``/mentor``      browse the pentest learning path
- ``/health``      liveness probe (used by tests)

This is a local operator tool: it scans local paths on the machine it runs on,
so it binds to 127.0.0.1 by default. It exposes only the defensive scanner and
the mentor — never Range's target-facing commands — over HTTP.
"""

from __future__ import annotations

import html
from typing import Any

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse

from cloudnova import __version__, service
from cloudnova.range import active_persona
from cloudnova.range.mentor import learning_path

_STYLE = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font: 15px/1.5 system-ui, sans-serif; margin: 0; background: #f6f7f9; color: #111; }
a { color: #2563eb; text-decoration: none; } a:hover { text-decoration: underline; }
header { background: #0f172a; color: #fff; padding: 16px 24px; display: flex;
         align-items: baseline; gap: 16px; flex-wrap: wrap; }
header .brand { font-size: 20px; font-weight: 800; }
header .tag { color: #94a3b8; font-size: 13px; }
nav a { color: #cbd5e1; margin-right: 16px; }
main { max-width: 960px; margin: 0 auto; padding: 24px; }
.card { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px;
        padding: 18px 20px; margin: 16px 0; }
input[type=text] { width: 100%; padding: 10px; border: 1px solid #cbd5e1; border-radius: 8px;
        font: inherit; }
button { background: #2563eb; color: #fff; border: 0; border-radius: 8px; padding: 10px 18px;
        font: inherit; font-weight: 600; cursor: pointer; margin-top: 10px; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #eee; vertical-align: top; }
.sev { font-weight: 700; padding: 2px 8px; border-radius: 4px; color: #fff; font-size: 12px; }
.critical { background: #b3123b; } .high { background: #d1453b; } .medium { background: #c77700; }
.low { background: #1f7a8c; } .info { background: #6b7280; }
.grade { font-size: 40px; font-weight: 800; }
.muted { color: #6b7280; }
@media (prefers-color-scheme: dark) {
  body { background: #0b0c0e; color: #e8e8ea; }
  .card { background: #17181c; border-color: #2a2b31; }
  input[type=text] { background: #0f1013; color: #e8e8ea; border-color: #2a2b31; }
  th, td { border-color: #2a2b31; }
}
"""

_GRADE_COLOR = {"A": "#1a7f37", "B": "#1a7f37", "C": "#c77700", "D": "#d1453b", "F": "#b3123b"}


def _e(v: object) -> str:
    return html.escape(str(v), quote=True)


def _page(title: str, body: str) -> str:
    p = active_persona()
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)} — CloudNova</title><style>{_STYLE}</style></head>
<body>
<header>
  <span class="brand">🛡️ CloudNova</span>
  <span class="tag">{_e(p.display_name)} · v{_e(__version__)}</span>
  <nav style="margin-left:auto">
    <a href="/">Home</a><a href="/scan">Scan</a><a href="/mentor">Mentor</a>
  </nav>
</header>
<main>{body}</main>
</body></html>"""


def create_app() -> FastAPI:
    app = FastAPI(title="CloudNova", version=__version__)

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__}

    @app.get("/", response_class=HTMLResponse)
    def home() -> str:
        body = """
        <div class="card">
          <h1>Cloud security, from scan to attack path.</h1>
          <p class="muted">Scan Terraform, CloudFormation, Kubernetes, and cloud logs
          for misconfigurations, see exploitable attack chains, and get a posture grade.</p>
          <p><a href="/scan">→ Run a scan</a> &nbsp;·&nbsp;
          <a href="/mentor">→ Open the pentest mentor</a></p>
        </div>
        <div class="card">
          <h2>What it checks</h2>
          <p class="muted">25+ checks across 5 formats, mapped to CIS &amp; MITRE ATT&amp;CK —
          plus secret scanning, IAM analysis, and cross-resource attack-path detection.</p>
        </div>"""
        return _page("Home", body)

    @app.get("/scan", response_class=HTMLResponse)
    def scan_form() -> str:
        return _page("Scan", _scan_form_body())

    @app.post("/scan", response_class=HTMLResponse)
    def run_scan(path: str = Form(...)) -> str:
        try:
            result = service.scan(path)
        except FileNotFoundError:
            return _page("Scan", _scan_form_body(error=f"Path not found: {path}"))
        return _page("Scan results", _scan_results_body(path, result))

    @app.get("/mentor", response_class=HTMLResponse)
    def mentor_page() -> str:
        rows = "".join(
            f"<tr><td>{s.order}</td><td><b>{_e(s.module.title)}</b><br>"
            f"<span class='muted'>{_e(s.module.summary)}</span></td>"
            f"<td class='muted'>{_e(s.module.level)}</td></tr>"
            for s in learning_path()
        )
        body = f"""
        <div class="card">
          <h1>Pentest mentor — learning path</h1>
          <p class="muted">A guided path from foundations to job- and cert-ready. Use the CLI
          (<code>cloudnova range mentor</code>) for topics, cert tracks, and guided labs.</p>
          <table><thead><tr><th>#</th><th>Module</th><th>Level</th></tr></thead>
          <tbody>{rows}</tbody></table>
        </div>"""
        return _page("Mentor", body)

    return app


def _scan_form_body(error: str = "") -> str:
    err = f'<p style="color:#d1453b">{_e(error)}</p>' if error else ""
    return f"""
    <div class="card">
      <h1>Run a scan</h1>
      <p class="muted">Enter a path to a file or directory on this machine.</p>
      {err}
      <form method="post" action="/scan">
        <input type="text" name="path" placeholder="./infra or /path/to/terraform" autofocus>
        <button type="submit">Scan</button>
      </form>
    </div>"""


def _scan_results_body(path: str, result: dict[str, Any]) -> str:
    summary = result["summary"]
    grade = summary["grade"]
    color = _GRADE_COLOR.get(grade, "#6b7280")
    counts = summary["severity_counts"]
    pills = " ".join(f'<span class="sev {sev}">{sev}: {n}</span>' for sev, n in counts.items() if n)

    def _row(f: dict[str, Any]) -> str:
        loc = f["location"].get("resource") or f["location"]["path"]
        return (
            f'<tr><td><span class="sev {f["severity"]}">{_e(f["severity"].upper())}</span></td>'
            f'<td><b>{_e(f["title"])}</b><br><span class="muted">{_e(f["description"])}</span>'
            f'<br><span class="muted">↳ {_e(f["remediation"])}</span></td>'
            f'<td class="muted">{_e(loc)}</td></tr>'
        )

    rows = (
        "".join(_row(f) for f in result["findings"])
        or '<tr><td colspan="3" class="muted">No findings. 🎉</td></tr>'
    )

    return f"""
    <div class="card" style="display:flex;gap:24px;align-items:center;flex-wrap:wrap">
      <div><div class="grade" style="color:{color}">{_e(grade)}</div>
        <div class="muted">{summary["posture_score"]}/100 · lower is better</div></div>
      <div>
        <h1 style="margin:0">Scan results</h1>
        <p class="muted" style="margin:6px 0">{_e(path)} — {summary["files_scanned"]} file(s),
        {summary["findings"]} finding(s)</p>
        <div>{pills}</div>
      </div>
    </div>
    <div class="card">
      <table><thead><tr><th>Severity</th><th>Finding</th><th>Resource</th></tr></thead>
      <tbody>{rows}</tbody></table>
    </div>
    <p><a href="/scan">← Run another scan</a></p>"""
