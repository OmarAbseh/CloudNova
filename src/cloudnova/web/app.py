"""The FastAPI application: a polished local dashboard for CloudNova.

Server-rendered HTML reusing the tested ``service`` and ``range`` layers. The look
is a dark, red-accented security aesthetic with a 3D animated hero (Three.js, loaded
from a CDN as progressive enhancement — the page works fully without it).

Routes:
- ``/``        landing page + 3D hero + capabilities
- ``/scan``    run a scan and view findings / score / attack paths
- ``/mentor``  the pentest learning path
- ``/health``  liveness probe (tests)

Local operator tool: scans local paths, binds to 127.0.0.1, and exposes only the
defensive scanner and mentor over HTTP — never Range's target-facing commands.
"""

from __future__ import annotations

import html
from typing import Any

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse

from cloudnova import __version__, service
from cloudnova.range import active_persona
from cloudnova.range.mentor import learning_path

# Three.js (UMD, exposes global THREE). Progressive enhancement only.
_THREE_CDN = "https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"

# Dark, red-accented palette — deliberately not the default warm Claude tones.
_STYLE = """
:root {
  --bg:#0a0a0d; --panel:#141419; --panel2:#1b1b22; --line:#26262f;
  --text:#ececef; --muted:#8b8b99;
  --red:#ff2e4d; --red2:#b3123b; --pink:#ff6b81;
  --grad:linear-gradient(135deg,#ff2e4d 0%,#b3123b 60%,#7a0b28 100%);
  color-scheme: dark;
}
* { box-sizing:border-box; }
html,body { margin:0; }
body { font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
  background:radial-gradient(1200px 600px at 70% -10%,#1a0d12 0%,var(--bg) 55%);
  color:var(--text); min-height:100vh; }
a { color:var(--pink); text-decoration:none; } a:hover { color:var(--red); }
code { background:#000; padding:1px 6px; border-radius:5px; color:var(--pink);
  font-family:ui-monospace,"SF Mono",Menlo,monospace; font-size:.9em; }

header { position:sticky; top:0; z-index:10; display:flex; align-items:center; gap:20px;
  padding:14px 28px; background:rgba(10,10,13,.72); backdrop-filter:blur(12px);
  border-bottom:1px solid var(--line); }
.brand { font-weight:800; font-size:19px; letter-spacing:.3px; display:flex; align-items:center; gap:9px; }
.brand .dot { width:11px; height:11px; border-radius:50%; background:var(--grad);
  box-shadow:0 0 14px 2px rgba(255,46,77,.7); }
.brand .sub { color:var(--muted); font-weight:500; font-size:12px; }
nav { margin-left:auto; display:flex; gap:6px; }
nav a { color:var(--muted); padding:7px 14px; border-radius:8px; font-weight:600; font-size:14px; }
nav a:hover { color:var(--text); background:var(--panel2); }

main { max-width:1000px; margin:0 auto; padding:28px 24px 64px; }

.hero { position:relative; display:grid; grid-template-columns:1.1fr .9fr; gap:24px;
  align-items:center; min-height:340px; margin:12px 0 8px; }
.hero h1 { font-size:44px; line-height:1.05; margin:0 0 14px; letter-spacing:-1px; }
.hero h1 .accent { background:var(--grad); -webkit-background-clip:text;
  background-clip:text; color:transparent; }
.hero p { color:var(--muted); font-size:17px; max-width:44ch; }
.hero-3d { position:relative; height:320px; }
#hero3d { width:100%; height:100%; display:block; }
/* CSS fallback orb (shown if Three.js doesn't load) */
.orb { position:absolute; inset:0; margin:auto; width:220px; height:220px; border-radius:50%;
  background:radial-gradient(circle at 35% 30%,rgba(255,107,129,.55),rgba(179,18,59,.15) 60%,transparent 70%);
  filter:blur(4px); animation:float 6s ease-in-out infinite; }
@keyframes float { 0%,100%{transform:translateY(-8px)} 50%{transform:translateY(8px)} }

.btn { display:inline-block; padding:12px 22px; border-radius:10px; font-weight:700;
  background:var(--grad); color:#fff; border:0; cursor:pointer; font-size:15px;
  box-shadow:0 8px 24px -8px rgba(255,46,77,.6); transition:transform .12s ease; }
.btn:hover { transform:translateY(-2px); color:#fff; }
.btn.ghost { background:transparent; border:1px solid var(--line); color:var(--text);
  box-shadow:none; }

.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:16px; margin-top:8px; }
.card { background:linear-gradient(180deg,var(--panel) 0%,var(--panel2) 100%);
  border:1px solid var(--line); border-radius:14px; padding:20px; transition:border-color .15s,transform .15s; }
.card:hover { border-color:var(--red2); transform:translateY(-3px); }
.card h3 { margin:0 0 6px; font-size:16px; }
.card p { color:var(--muted); margin:0; font-size:14px; }
.kicker { color:var(--red); font-weight:700; font-size:12px; letter-spacing:2px; text-transform:uppercase; }

input[type=text] { width:100%; padding:13px 14px; border:1px solid var(--line); border-radius:10px;
  font:inherit; background:#0c0c10; color:var(--text); }
input[type=text]:focus { outline:none; border-color:var(--red); box-shadow:0 0 0 3px rgba(255,46,77,.15); }

table { width:100%; border-collapse:collapse; }
th,td { text-align:left; padding:10px 12px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:1px; }
.sev { font-weight:800; padding:3px 9px; border-radius:6px; color:#fff; font-size:11px; letter-spacing:.5px; }
.critical{background:#e11d48}.high{background:#f43f5e}.medium{background:#d97706}.low{background:#0891b2}.info{background:#525252}
.grade { font-size:56px; font-weight:900; line-height:1; }
.muted { color:var(--muted); }
.summary { display:flex; gap:26px; align-items:center; flex-wrap:wrap; }
.pills { display:flex; gap:8px; flex-wrap:wrap; margin-top:8px; }

@media (max-width:760px){ .hero{grid-template-columns:1fr} .hero-3d{height:220px} .hero h1{font-size:34px} }
"""

_GRADE_COLOR = {"A": "#22c55e", "B": "#22c55e", "C": "#d97706", "D": "#f43f5e", "F": "#e11d48"}


def _e(v: object) -> str:
    return html.escape(str(v), quote=True)


def _hero_script() -> str:
    return f"""
<script src="{_THREE_CDN}"></script>
<script>
(function(){{
  if(!window.THREE) return;
  var c=document.getElementById('hero3d'); if(!c) return;
  try {{
    var w=c.clientWidth||400, h=c.clientHeight||320;
    var scene=new THREE.Scene();
    var cam=new THREE.PerspectiveCamera(60,w/h,0.1,100); cam.position.z=3.4;
    var rnd=new THREE.WebGLRenderer({{canvas:c,alpha:true,antialias:true}});
    rnd.setSize(w,h); rnd.setPixelRatio(Math.min(window.devicePixelRatio,2));
    var geo=new THREE.IcosahedronGeometry(1.5,1);
    var line=new THREE.LineSegments(new THREE.WireframeGeometry(geo),
      new THREE.LineBasicMaterial({{color:0xff2e4d,transparent:true,opacity:0.9}}));
    var pts=new THREE.Points(geo,new THREE.PointsMaterial({{color:0xff6b81,size:0.06}}));
    scene.add(line); scene.add(pts);
    var orb=document.querySelector('.orb'); if(orb) orb.style.display='none';
    (function loop(){{ requestAnimationFrame(loop);
      line.rotation.y+=0.004; line.rotation.x+=0.0016; pts.rotation.copy(line.rotation);
      rnd.render(scene,cam); }})();
    window.addEventListener('resize',function(){{ w=c.clientWidth; h=c.clientHeight;
      cam.aspect=w/h; cam.updateProjectionMatrix(); rnd.setSize(w,h); }});
  }} catch(e) {{ /* leave the CSS orb fallback in place */ }}
}})();
</script>"""


def _page(title: str, body: str, *, hero: bool = False) -> str:
    p = active_persona()
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)} — CloudNova</title><style>{_STYLE}</style></head>
<body>
<header>
  <span class="brand"><span class="dot"></span>CloudNova
    <span class="sub">{_e(p.display_name)} · v{_e(__version__)}</span></span>
  <nav><a href="/">Home</a><a href="/scan">Scan</a><a href="/mentor">Mentor</a></nav>
</header>
<main>{body}</main>
{_hero_script() if hero else ""}
</body></html>"""


def create_app() -> FastAPI:
    app = FastAPI(title="CloudNova", version=__version__)

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__}

    @app.get("/", response_class=HTMLResponse)
    def home() -> str:
        body = """
        <section class="hero">
          <div>
            <div class="kicker">Cloud security · offensive &amp; defensive</div>
            <h1>Find the <span class="accent">attack path</span><br>before they do.</h1>
            <p>Scan your cloud for misconfigurations, chain them into real attack paths,
               grade your posture, and train to break in — all in one tool.</p>
            <p style="margin-top:20px">
              <a class="btn" href="/scan">Run a scan →</a>
              <a class="btn ghost" href="/mentor">Open the mentor</a>
            </p>
          </div>
          <div class="hero-3d"><canvas id="hero3d"></canvas><div class="orb"></div></div>
        </section>

        <div class="grid">
          <div class="card"><div class="kicker">Scan</div><h3>30+ checks, 5 formats</h3>
            <p>Terraform, CloudFormation, Kubernetes, CloudTrail &amp; logs — mapped to CIS &amp; MITRE ATT&amp;CK.</p></div>
          <div class="card"><div class="kicker">Graph</div><h3>Attack paths</h3>
            <p>Exposed compute → over-privileged role → sensitive data, chained automatically.</p></div>
          <div class="card"><div class="kicker">IAM</div><h3>Author &amp; audit</h3>
            <p>Generate least-privilege policies and catch privilege-escalation vectors.</p></div>
          <div class="card"><div class="kicker">Range</div><h3>Learn to hack</h3>
            <p>An authorization-first pentest toolkit and a tutor that takes you to job-ready.</p></div>
        </div>"""
        return _page("Home", body, hero=True)

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
        <div class="kicker">Range · Mentor</div>
        <h1 style="margin:4px 0 4px">Your path to pentester</h1>
        <p class="muted" style="margin-top:0">Foundations to job- and cert-ready. Use
        <code>cloudnova range mentor</code> for topics, cert tracks, and guided labs.</p>
        <div class="card" style="margin-top:16px">
          <table><thead><tr><th>#</th><th>Module</th><th>Level</th></tr></thead>
          <tbody>{rows}</tbody></table>
        </div>"""
        return _page("Mentor", body)

    return app


def _scan_form_body(error: str = "") -> str:
    err = f'<p style="color:var(--red)">{_e(error)}</p>' if error else ""
    return f"""
    <div class="kicker">Scanner</div>
    <h1 style="margin:4px 0">Run a scan</h1>
    <p class="muted">Enter a path to a file or directory on this machine.</p>
    <div class="card" style="margin-top:14px">
      {err}
      <form method="post" action="/scan">
        <input type="text" name="path" placeholder="./infra or /path/to/terraform" autofocus>
        <p><button class="btn" type="submit">Scan →</button></p>
      </form>
    </div>"""


def _scan_results_body(path: str, result: dict[str, Any]) -> str:
    summary = result["summary"]
    grade = summary["grade"]
    color = _GRADE_COLOR.get(grade, "#8b8b99")
    counts = summary["severity_counts"]
    pills = " ".join(f'<span class="sev {s}">{s}: {n}</span>' for s, n in counts.items() if n)

    def _row(f: dict[str, Any]) -> str:
        loc = f["location"].get("resource") or f["location"]["path"]
        return (
            f'<tr><td><span class="sev {f["severity"]}">{_e(f["severity"].upper())}</span></td>'
            f'<td><b>{_e(f["title"])}</b><br><span class="muted">{_e(f["description"])}</span>'
            f'<br><span class="muted">↳ {_e(f["remediation"])}</span></td>'
            f'<td class="muted">{_e(loc)}</td></tr>'
        )

    rows = "".join(_row(f) for f in result["findings"]) or (
        '<tr><td colspan="3" class="muted">No findings. 🎉</td></tr>'
    )
    return f"""
    <div class="card summary">
      <div><div class="grade" style="color:{color}">{_e(grade)}</div>
        <div class="muted">{summary["posture_score"]}/100 · lower is better</div></div>
      <div>
        <div class="kicker">Results</div>
        <h1 style="margin:2px 0">{summary["findings"]} finding(s)</h1>
        <p class="muted" style="margin:2px 0">{_e(path)} — {summary["files_scanned"]} file(s) scanned</p>
        <div class="pills">{pills}</div>
      </div>
    </div>
    <div class="card">
      <table><thead><tr><th>Severity</th><th>Finding</th><th>Resource</th></tr></thead>
      <tbody>{rows}</tbody></table>
    </div>
    <p><a class="btn ghost" href="/scan">← Run another scan</a></p>"""
