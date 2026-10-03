"""In-product guide: how to use CloudNova, and how to read what it tells you.

Separate from the mentor. The mentor teaches penetration testing as a subject;
this teaches the tool. Someone who has just signed up needs to know what to put
in the scan box and what a grade of D means, not how to enumerate a subnet.

Written as prose with worked examples rather than a feature tour, because the
questions people actually arrive with are "what do I point this at" and "which
of these 32 findings do I fix first".
"""

from __future__ import annotations

import html


def _e(v: object) -> str:
    return html.escape(str(v), quote=True)


def _section(anchor: str, heading: str, body: str) -> str:
    return f'<section id="{_e(anchor)}" class="guide-s"><h2>{_e(heading)}</h2>{body}</section>'


_CONTENTS = (
    ("first-scan", "Run your first scan"),
    ("reading", "Reading a result"),
    ("severity", "Severity and confidence are different"),
    ("history", "Tracking drift over time"),
    ("team", "Organizations, roles and invitations"),
    ("ci", "Wiring it into CI"),
    ("cli", "The command line"),
    ("limits", "Plan limits"),
)


def guide_body() -> str:
    toc = "".join(f'<li><a href="#{_e(a)}">{_e(t)}</a></li>' for a, t in _CONTENTS)

    first = """
    <p>Point a scan at a directory of infrastructure code. CloudNova reads
      Terraform, CloudFormation and Kubernetes manifests, plus CloudTrail and
      log files, and reports what is misconfigured.</p>
    <p>On the <a href="/scan">Scan</a> page, enter a path on this machine:</p>
    <pre>./infra
/home/you/projects/acme/terraform
examples</pre>
    <p><code>examples</code> ships with CloudNova and contains deliberately
      insecure infrastructure, so it is the fastest way to see a real result
      before pointing it at anything of yours. It produces around 30 findings.</p>
    <p>Nothing leaves this machine during a scan. Files are read locally, and
      only the finished result is saved to your organization.</p>"""

    reading = """
    <p>A result opens with a grade from A to F and a score out of 100, where
      lower is better. The score is a weighted sum: each finding contributes
      points according to severity, and every exploitable attack path adds a
      flat penalty on top of the findings it is built from.</p>
    <p>The score is never a black box. Every input that produced it is shown in
      the breakdown, so you can always answer "why is this a D".</p>
    <p>Each finding tells you what is wrong, where, and how to fix it.
      <b>Explain</b> expands a plain-English walkthrough: what an attacker does
      with it, and the concrete change that closes it.</p>
    <h3>Fix in this order</h3>
    <p>Start with attack paths, not with the longest list. A path means several
      findings chain into something exploitable end to end, for example an
      internet-facing machine that can assume an over-privileged role that can
      reach your data. One fix anywhere along the chain breaks it, which buys
      more than clearing a dozen unrelated low findings.</p>"""

    severity = """
    <p>These two are reported separately on purpose, and conflating them is how
      scanners end up ignored.</p>
    <p><b>Severity</b> is how bad the issue is if it is real. <b>Confidence</b>
      is how sure the check is that it is real.</p>
    <p>A bucket whose name merely contains the word "public" is low confidence:
      the name proves nothing. An IAM policy document parsed and found to grant
      <code>Action: "*"</code> is high confidence, because the evidence is the
      policy itself.</p>
    <p>A critical finding at low confidence deserves a look. A low finding at
      high confidence is a known, small problem. Treating those as the same
      number is what trains people to close the tab.</p>"""

    history = """
    <p>Every scan is saved against your organization and listed under
      <a href="/history">History</a>, newest first, with its grade and finding
      count. Open one to see exactly what it found at that moment.</p>
    <p>What matters is not a single number but the direction it moves. A run of
      scans on the same target is the honest answer to "is our posture getting
      better", and it is the thing worth putting in front of an auditor or a
      board.</p>
    <p>For continuous monitoring, run <code>cloudnova monitor</code> from cron
      or CI with <code>--fail-on-new</code>. It compares each scan to the
      previous one and exits non-zero when something new appears, so a
      regression pages you instead of waiting to be noticed.</p>"""

    team = """
    <p>Everything you scan belongs to an <b>organization</b>, not to you
      personally. Your first one is created automatically on first sign-in, and
      you can create more from
      <a href="/org">Organization</a>. The picker in the header chooses which
      one a scan is saved to.</p>
    <h3>Roles</h3>
    <table class="roles">
      <tbody>
        <tr><td><span class="rolechip owner">owner</span></td>
            <td>Everything, including roles and deleting the organization.</td></tr>
        <tr><td><span class="rolechip admin">admin</span></td>
            <td>Invite and remove people, manage targets and scans.</td></tr>
        <tr><td><span class="rolechip member">member</span></td>
            <td>Run and save scans.</td></tr>
        <tr><td><span class="rolechip viewer">viewer</span></td>
            <td>Read only.</td></tr>
      </tbody>
    </table>
    <p>Invite someone by email from the Organization page and they see the
      invitation under <a href="/invites">Invitations</a> the next time they
      sign in with that address. Invitations expire after 14 days.</p>
    <p>Isolation is enforced by the database, not by this interface. A member of
      one organization cannot read another's scans, findings or members even by
      guessing an address, because every query is evaluated against their own
      identity before it returns a row.</p>"""

    ci = """
    <p>CloudNova ships as a GitHub Action. It scans on every push, uploads
      findings to GitHub code scanning, and fails the build on high severity.</p>
    <pre>name: CloudNova
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: OmarAbseh/CloudNova@&lt;commit-sha&gt;
        with:
          path: .
          fail-on: high</pre>
    <p>Pin to a commit rather than a branch. A branch is whatever it points at
      when the workflow runs, and this action installs and runs a package.</p>"""

    cli = """
    <p>The dashboard covers scanning and your team. The command line goes
      further, and is where scheduled scanning and report export live.</p>
    <pre>cloudnova scan ./infra                 # scan, human readable
cloudnova scan ./infra --format sarif  # for code scanning
cloudnova compliance ./infra --framework all --out report.md
cloudnova monitor ./infra --fail-on-new
cloudnova history ./infra              # posture trend
cloudnova triage ./infra               # AI explanation per finding</pre>
    <p>Run <code>cloudnova --help</code> for the full set.</p>"""

    limits = """
    <p>Each plan sets how many people can be in an organization and how many
      scans it can run per month. Current usage is shown on the
      <a href="/org">Organization</a> page.</p>
    <p>A pending invitation holds a seat until it is accepted or revoked, so an
      invitation you have forgotten about still counts. Revoke it to free the
      seat.</p>
    <p>Scan counts reset at the start of each calendar month. Going over a seat
      limit never removes anyone's access, it only stops the next invitation.</p>"""

    sections = (
        _section("first-scan", "Run your first scan", first)
        + _section("reading", "Reading a result", reading)
        + _section("severity", "Severity and confidence are different", severity)
        + _section("history", "Tracking drift over time", history)
        + _section("team", "Organizations, roles and invitations", team)
        + _section("ci", "Wiring it into CI", ci)
        + _section("cli", "The command line", cli)
        + _section("limits", "Plan limits", limits)
    )

    return f"""
    <div class="guide">
      <aside class="guide-toc">
        <h2>Guide</h2>
        <ol>{toc}</ol>
        <p class="muted" style="font-size:13px;margin-top:14px">
          Learning offensive security itself? That is the
          <a href="/mentor">mentor</a>.</p>
      </aside>
      <div class="guide-body">
        <h1 style="margin:0 0 6px">How to use CloudNova</h1>
        <p class="muted" style="margin:0 0 4px">Scanning infrastructure, reading
          what comes back, and working as a team.</p>
        {sections}
      </div>
    </div>"""
