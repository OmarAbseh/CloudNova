"""The engagement report: a print-ready document for a client.

Different from ``html_report``, which is a shareable snapshot of a scan. This
is the deliverable a paid assessment is actually bought for: a document with a
cover, an executive summary a non-engineer can act on, a stated scope, and
findings written to be handed to somebody who was not in the room.

Single self-contained file, no scripts and no external assets, because it gets
emailed and printed and read offline. Print styling is real rather than
decorative: Print to PDF in any browser produces the finished artefact, which
avoids a native PDF dependency and keeps the output auditable as text.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import UTC, datetime

from cloudnova.compliance.engine import ControlState, assess_all
from cloudnova.compliance.frameworks import Framework
from cloudnova.core.engine import ScanResult
from cloudnova.core.findings import Finding, Severity
from cloudnova.scoring import posture_score

_SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "#9f1239",
    Severity.HIGH: "#f43f5e",
    Severity.MEDIUM: "#d97706",
    Severity.LOW: "#0891b2",
    Severity.INFO: "#525252",
}

_GRADE_COLOR = {"A": "#15803d", "B": "#15803d", "C": "#b45309", "D": "#be123c", "F": "#9f1239"}

# Enum values are slugs. A client-facing document spells the standards out.
_FRAMEWORK_NAMES = {
    Framework.ISO_27001: "ISO/IEC 27001",
    Framework.NIST_CSF: "NIST Cybersecurity Framework",
    Framework.PCI_DSS: "PCI DSS",
    Framework.SOC_2: "SOC 2",
    Framework.CIS_V8: "CIS Controls v8",
}

# A plain-English verdict per grade. The person signing off on remediation
# budget is usually not the person who wrote the Terraform.
_VERDICT = {
    "A": (
        "No material exposure was identified in the reviewed scope. The "
        "configuration follows the hardening practices expected of a production "
        "estate."
    ),
    "B": (
        "The estate is broadly well configured. The issues identified are worth "
        "closing but none of them, alone, gives an attacker a route in."
    ),
    "C": (
        "Several weaknesses were identified that together reduce the margin of "
        "safety. None is immediately exploitable in isolation, but the estate "
        "depends on more things going right than it should."
    ),
    "D": (
        "Material weaknesses were identified, including at least one that an "
        "attacker could use directly. Remediation should be scheduled rather "
        "than queued."
    ),
    "F": (
        "Critical exposure was identified. One or more issues are directly "
        "exploitable from outside the estate and should be treated as an "
        "incident-prevention priority rather than a backlog item."
    ),
}


@dataclass(frozen=True)
class EngagementMeta:
    """Who the report is for, and what was examined.

    Scope is a free-text string recorded verbatim rather than inferred from the
    path, because what was and was not examined is the first thing a dispute
    turns on and it deserves to be stated by a human.
    """

    client: str
    engagement: str
    scope: str
    assessor: str
    reference: str = ""


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _severity_counts(findings: list[Finding]) -> dict[Severity, int]:
    counts = dict.fromkeys(Severity, 0)
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def _pill(severity: Severity, count: int) -> str:
    return (
        f'<div class="pill"><span class="sw" style="background:{_SEVERITY_COLOR[severity]}">'
        f"</span><b>{count}</b> {_e(severity.value)}</div>"
    )


def _finding_block(index: int, finding: Finding) -> str:
    loc = finding.location
    where = _e(loc.resource or loc.path)
    line = f" (line {loc.line})" if loc.line else ""
    mappings = []
    if finding.cis_controls:
        mappings.append("CIS: " + ", ".join(_e(c) for c in finding.cis_controls))
    if finding.mitre_attack:
        mappings.append("MITRE ATT&amp;CK: " + ", ".join(_e(m) for m in finding.mitre_attack))
    mapping_row = (
        f"<tr><th>Mapping</th><td>{' &middot; '.join(mappings)}</td></tr>" if mappings else ""
    )
    evidence_row = (
        f"<tr><th>Evidence</th><td><code>{_e(finding.evidence)}</code></td></tr>"
        if finding.evidence
        else ""
    )
    refs = (
        "<tr><th>References</th><td>"
        + "<br>".join(_e(r) for r in finding.references)
        + "</td></tr>"
        if finding.references
        else ""
    )
    return f"""
    <article class="finding">
      <h3><span class="idx">{index}</span>{_e(finding.title)}
        <span class="sev" style="background:{_SEVERITY_COLOR[finding.severity]}">
          {_e(finding.severity.value)}</span></h3>
      <table class="meta">
        <tr><th>Location</th><td>{where}{line}<br>
          <span class="dim">{_e(loc.path)}</span></td></tr>
        <tr><th>Confidence</th><td>{_e(finding.confidence.value)}</td></tr>
        <tr><th>Rule</th><td><code>{_e(finding.check_id)}</code></td></tr>
        {mapping_row}
        {evidence_row}
      </table>
      <h4>What is wrong</h4>
      <p>{_e(finding.description)}</p>
      <h4>Recommended remediation</h4>
      <p>{_e(finding.remediation)}</p>
      <table class="meta">{refs}</table>
    </article>"""


def _compliance_appendix(check_ids: list[str]) -> str:
    reports = assess_all(check_ids)
    rows = []
    for framework, report in reports.items():
        # Compare against the enum, never a lowercase string. ControlState
        # values are uppercase, so a string comparison silently reports zero
        # failures, which in a client document is an overclaim.
        assessed = [c for c in report.controls if c.state is not ControlState.NOT_ASSESSED]
        failed = sum(1 for c in assessed if c.state is ControlState.FAIL)
        passed = len(assessed) - failed
        total = len(assessed)
        rows.append(
            f"<tr><td>{_e(_FRAMEWORK_NAMES.get(framework, framework.value.upper()))}</td>"
            f"<td>{total}</td><td>{passed}</td><td><b>{failed}</b></td></tr>"
        )
    if not rows:
        return ""
    return f"""
    <section class="page">
      <h2>Appendix A, compliance mapping</h2>
      <p>Findings in this report mapped onto the control sets below. A control is
        marked failed when at least one finding maps to it. This is an indicative
        mapping produced from configuration review, not a certification, and it
        does not replace an accredited audit.</p>
      <table class="grid">
        <thead><tr><th>Framework</th><th>Controls assessed</th>
          <th>No finding</th><th>At least one finding</th></tr></thead>
        <tbody>{"".join(rows)}</tbody>
      </table>
    </section>"""


def render_engagement(result: ScanResult, meta: EngagementMeta) -> str:
    """Render the full engagement report as one self-contained HTML document."""
    findings = result.sorted_findings()
    score = posture_score(result)
    counts = _severity_counts(findings)
    issued = datetime.now(UTC).strftime("%d %B %Y")
    grade_colour = _GRADE_COLOR.get(score.grade, "#525252")

    pills = "".join(_pill(s, counts[s]) for s in Severity if counts[s])
    if not pills:
        pills = '<div class="pill"><b>0</b> findings</div>'

    # Attack paths are reported as CRITICAL findings by the graph layer, so they
    # are pulled out by rule id rather than re-derived.
    paths = [f for f in findings if f.check_id.startswith("GRAPH_")]
    other = [f for f in findings if not f.check_id.startswith("GRAPH_")]

    if paths:
        path_blocks = "".join(
            f'<div class="path"><h4>{_e(p.title)}</h4><p>{_e(p.description)}</p>'
            f"<p><b>Recommended remediation.</b> {_e(p.remediation)}</p></div>"
            for p in paths
        )
        key_risks = f"""
        <section class="page">
          <h2>Key risks</h2>
          <p>The findings below chain several individually unremarkable
            misconfigurations into a route an attacker can follow end to end.
            Breaking the chain at any single point removes the path, which
            usually makes these the highest-value remediation in the report.</p>
          {path_blocks}
        </section>"""
    else:
        key_risks = f"""
        <section class="page">
          <h2>Key risks</h2>
          <p>No end-to-end attack path was identified in the reviewed scope. The
            findings in this report are individual weaknesses rather than links
            in a chain that reaches sensitive data. {
            "They should still be remediated on their own merits." if other else ""
        }</p>
        </section>"""

    if other:
        finding_blocks = "".join(_finding_block(i, f) for i, f in enumerate(other, start=1))
        findings_section = f"""
        <section class="page">
          <h2>Findings</h2>
          <p>Ordered most severe first. Each entry states what is wrong, where,
            how confident the assessment is, and what to change.</p>
          {finding_blocks}
        </section>"""
    else:
        findings_section = """
        <section class="page">
          <h2>Findings</h2>
          <p>No findings were identified in the reviewed scope.</p>
        </section>"""

    errors_note = ""
    if result.errors:
        items = "".join(f"<li>{_e(e)}</li>" for e in result.errors[:20])
        errors_note = f"""
        <h4>Files that could not be parsed</h4>
        <p>The following inputs were skipped and are therefore outside the
          assurance this report provides.</p>
        <ul class="errs">{items}</ul>"""

    reference = (
        f"<tr><th>Reference</th><td>{_e(meta.reference)}</td></tr>" if meta.reference else ""
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{_e(meta.engagement)}, {_e(meta.client)}</title>
<style>
  @page {{ size: A4; margin: 18mm 16mm 20mm; }}
  * {{ box-sizing: border-box; }}
  html, body {{ margin: 0; }}
  body {{ font: 10.5pt/1.55 "Helvetica Neue", Helvetica, Arial, sans-serif;
    color: #15151a; background: #fff; }}
  .sheet {{ max-width: 860px; margin: 0 auto; padding: 28px 30px 60px; }}

  h1 {{ font-size: 25pt; line-height: 1.12; margin: 0 0 10px; letter-spacing: -.5px; }}
  h2 {{ font-size: 15pt; margin: 0 0 10px; padding-bottom: 7px;
    border-bottom: 2px solid #15151a; }}
  h3 {{ font-size: 11.5pt; margin: 0 0 8px; }}
  h4 {{ font-size: 10pt; margin: 13px 0 3px; text-transform: none; color: #3f3f4a; }}
  p {{ margin: 0 0 9px; }}
  code {{ font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 9pt;
    background: #f3f3f5; border: 1px solid #e2e2e7; border-radius: 3px; padding: 0 4px; }}
  .dim {{ color: #71717a; font-size: 9pt; }}

  /* Cover */
  .cover {{ min-height: 232mm; display: flex; flex-direction: column; }}
  .cover .rule {{ height: 5px; background: #9f1239; width: 92px; margin: 0 0 26px; }}
  .cover .spacer {{ flex: 1; }}
  .cover dl {{ margin: 0; display: grid; grid-template-columns: 112px 1fr;
    row-gap: 5px; font-size: 10pt; }}
  .cover dt {{ color: #71717a; }}
  .cover dd {{ margin: 0; }}
  .notice {{ margin-top: 26px; padding: 11px 13px; border: 1px solid #e2e2e7;
    border-left: 3px solid #9f1239; background: #fafafa; font-size: 9pt; color: #3f3f4a; }}

  /* Each top-level section starts a page when printed. */
  .page {{ page-break-before: always; padding-top: 4px; }}

  .score {{ display: flex; align-items: center; gap: 22px; margin: 0 0 16px;
    padding: 16px 18px; border: 1px solid #e2e2e7; border-radius: 8px; }}
  .score .g {{ font-size: 44pt; font-weight: 800; line-height: 1; }}
  .score .n {{ font-size: 11pt; font-weight: 700; }}
  .pills {{ display: flex; gap: 8px; flex-wrap: wrap; margin: 0 0 14px; }}
  .pill {{ display: flex; align-items: center; gap: 6px; font-size: 9.5pt;
    border: 1px solid #e2e2e7; border-radius: 20px; padding: 3px 11px; }}
  .pill .sw {{ width: 9px; height: 9px; border-radius: 50%; display: inline-block; }}

  .finding {{ page-break-inside: avoid; border: 1px solid #e2e2e7; border-radius: 8px;
    padding: 14px 16px; margin: 0 0 13px; }}
  .finding h3 {{ display: flex; align-items: baseline; gap: 9px; }}
  .finding .idx {{ color: #a1a1aa; font-weight: 700; }}
  .sev {{ margin-left: auto; color: #fff; font-size: 7.5pt; font-weight: 800;
    letter-spacing: .4px; padding: 2px 7px; border-radius: 3px; text-transform: uppercase; }}
  table.meta {{ width: 100%; border-collapse: collapse; margin: 6px 0 0; }}
  table.meta th {{ text-align: left; width: 94px; vertical-align: top; color: #71717a;
    font-weight: 500; font-size: 9pt; padding: 2px 8px 2px 0; }}
  table.meta td {{ font-size: 9.5pt; padding: 2px 0; vertical-align: top; }}

  .path {{ page-break-inside: avoid; border-left: 3px solid #9f1239; background: #fafafa;
    padding: 12px 15px; margin: 0 0 12px; }}
  .path h4 {{ margin: 0 0 5px; font-size: 10.5pt; color: #15151a; }}

  table.grid {{ width: 100%; border-collapse: collapse; font-size: 9.5pt; }}
  table.grid th, table.grid td {{ text-align: left; padding: 6px 9px;
    border-bottom: 1px solid #e2e2e7; }}
  table.grid thead th {{ border-bottom: 2px solid #15151a; }}
  ul.errs {{ font-size: 9pt; color: #3f3f4a; }}

  @media print {{ .sheet {{ padding: 0; max-width: none; }} }}
</style></head>
<body><div class="sheet">

<section class="cover">
  <div class="rule"></div>
  <h1>{_e(meta.engagement)}</h1>
  <p style="font-size:13pt;color:#3f3f4a;margin:0 0 30px">{_e(meta.client)}</p>
  <dl>
    <dt>Client</dt><dd>{_e(meta.client)}</dd>
    <dt>Scope</dt><dd>{_e(meta.scope)}</dd>
    <dt>Assessor</dt><dd>{_e(meta.assessor)}</dd>
    <dt>Issued</dt><dd>{_e(issued)}</dd>
    {reference}
  </dl>
  <div class="spacer"></div>
  <div class="notice"><b>Confidential.</b> This report is prepared for
    {_e(meta.client)} and describes security weaknesses in their systems. It
    should be handled as sensitive material and shared only with those who need
    it to act on the findings.</div>
</section>

<section class="page">
  <h2>Executive summary</h2>
  <div class="score">
    <div class="g" style="color:{grade_colour}">{_e(score.grade)}</div>
    <div>
      <div class="n">{score.score} / 100 risk score</div>
      <div class="dim">Higher is worse. {result.files_scanned} file(s) examined,
        {result.checks_run} check(s) applied.</div>
    </div>
  </div>
  <div class="pills">{pills}</div>
  <h4>Risk posture</h4>
  <p>{_VERDICT.get(score.grade, "")}</p>
  <h4>How the score was reached</h4>
  <p>The score is a weighted sum rather than a judgement: each finding
    contributes points according to its severity, and every exploitable attack
    path adds a further penalty on top of the findings it is built from. Every
    input is listed so the number can be checked.</p>
  <table class="grid"><tbody>
    {"".join(f"<tr><td>{_e(k)}</td><td>{_e(v)}</td></tr>" for k, v in score.breakdown.items())}
  </tbody></table>
  {errors_note}
</section>

{key_risks}

{findings_section}

<section class="page">
  <h2>Methodology and limitations</h2>
  <h4>What was done</h4>
  <p>Infrastructure-as-code and configuration in the stated scope were parsed
    and evaluated against {result.checks_run} automated checks derived from the
    CIS Benchmarks and cloud provider hardening guidance. Cross-resource
    references were used to build a graph of the estate, and that graph was
    searched for routes from an internet-exposed resource to sensitive data.</p>
  <h4>Severity and confidence are separate</h4>
  <p>Each finding carries both. <b>Severity</b> is how serious the issue is if
    it is real. <b>Confidence</b> is how certain the assessment is that it is
    real. A bucket whose name merely contains the word "public" is low
    confidence, because the name proves nothing; a policy document parsed and
    found to grant every action is high confidence, because the evidence is the
    policy itself. Reporting one number instead of two is how scanners come to
    be ignored, so both are always shown.</p>
  <h4>Limitations</h4>
  <p>This assessment reviewed declared configuration in the stated scope. It did
    not execute exploits, did not test running applications for logic flaws, and
    makes no statement about resources outside that scope or changes made after
    the issue date. Anything excluded from scope is excluded from the assurance
    this report provides. An indicative compliance mapping is included; it is not
    a certification and does not replace an accredited audit.</p>
</section>

{_compliance_appendix([f.check_id for f in findings])}

</div></body></html>"""
