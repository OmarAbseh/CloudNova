"""Render a checklist run as an engagement report in the DarkShield layout.

Produces Markdown with the standard sections (confidentiality, scope, executive
summary, vulnerability summary table, technical findings) plus a full checklist
appendix. Severity counts follow the Critical/High/Moderate/Low/Informational
scale used in the vulnerability summary table.
"""

from __future__ import annotations

from datetime import date

from cloudnova.core.findings import Severity
from cloudnova.range.checklist.model import ChecklistRun, RunItem, State

# Severity for each finding id when it FAILs (default MEDIUM).
_SEVERITY: dict[str, Severity] = {
    "ATHN-001": Severity.HIGH,
    "CONF-004": Severity.HIGH,
    "CONF-002": Severity.HIGH,
    "CONF-005": Severity.HIGH,
    "CONF-006": Severity.MEDIUM,
    "CONF-007": Severity.MEDIUM,
    "CONF-008": Severity.HIGH,
    "SESS-002": Severity.MEDIUM,
    "CLNT-009": Severity.MEDIUM,
    "INPV-001": Severity.HIGH,
    "INPV-005": Severity.CRITICAL,
    "ATHZ-001": Severity.HIGH,
}

# DarkShield summary scale <- CloudNova severity.
_SCALE = ("Critical", "High", "Moderate", "Low", "Informational")
_SEV_TO_SCALE = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Moderate",
    Severity.LOW: "Low",
    Severity.INFO: "Informational",
}


def severity_for(item_id: str) -> Severity:
    return _SEVERITY.get(item_id, Severity.MEDIUM)


def summary_counts(run: ChecklistRun) -> dict[str, int]:
    """Count findings by the DarkShield severity scale."""
    counts = dict.fromkeys(_SCALE, 0)
    for ri in run.failed:
        counts[_SEV_TO_SCALE[severity_for(ri.item.id)]] += 1
    counts["Informational"] += len(run.by_state(State.INFO))
    return counts


def _remediation(item_id: str) -> str:
    fixes = {
        "ATHN-001": "Serve exclusively over HTTPS and redirect all HTTP to HTTPS.",
        "CONF-007": "Add a Strict-Transport-Security header with a long max-age.",
        "CONF-008": "Restrict CORS to an allow-list; never pair '*' with credentials.",
        "CONF-004": "Remove backup/unreferenced files from the web root.",
        "CONF-005": "Enforce authentication and IP allow-listing on admin interfaces.",
        "CONF-006": "Disable unused HTTP methods (PUT/DELETE/TRACE).",
        "SESS-002": "Set Secure, HttpOnly, and SameSite on session cookies.",
        "CLNT-009": "Set X-Frame-Options: DENY or a frame-ancestors CSP.",
        "INPV-001": "Context-encode all output and apply a strict CSP.",
        "INPV-005": "Use parameterized queries / prepared statements everywhere.",
        "ATHZ-001": "Canonicalize and validate file paths; deny traversal sequences.",
    }
    return fixes.get(item_id, "Remediate per OWASP guidance for this test case.")


def render_report(run: ChecklistRun, *, client: str = "[CLIENT NAME]") -> str:
    counts = summary_counts(run)
    fails = run.failed
    ds = [f"DS-{i + 1:03d}" for i in range(len(fails))]

    lines: list[str] = []
    lines.append(f"# Vulnerability Report — {client} — {date.today():%B %Y}\n")
    lines.append("## 1. Confidentiality Statement")
    lines.append(
        f"This document is the exclusive property of {client} and contains proprietary "
        "and confidential information. A penetration test is a snapshot in time; findings "
        "reflect the state observed during the assessment.\n"
    )
    lines.append("## 2. Assessment Overview & Authorization")
    lines.append(f"- **Target:** {run.target}")
    lines.append(f"- **Authorization:** {run.attestation}")
    lines.append("- **Scope Exclusion / Client Allowances:** as agreed in the scope file.\n")

    lines.append("## 3. Finding Severity Ratings")
    lines.append("Critical > High > Moderate > Low > Informational.\n")

    lines.append("## 4. Executive Summary")
    total = sum(counts[s] for s in ("Critical", "High", "Moderate", "Low"))
    lines.append(
        f"The assessment identified **{total}** vulnerabilities and "
        f"{counts['Informational']} informational observations on {run.target}.\n"
    )

    lines.append("## 5. Vulnerability Summary\n")
    lines.append("| " + " | ".join(_SCALE) + " |")
    lines.append("|" + "---|" * len(_SCALE))
    lines.append("| " + " | ".join(str(counts[s]) for s in _SCALE) + " |\n")
    lines.append("| ID | Finding | Severity | Recommendation |")
    lines.append("|---|---|---|---|")
    for tag, ri in zip(ds, fails, strict=True):
        sev = _SEV_TO_SCALE[severity_for(ri.item.id)]
        lines.append(
            f"| {tag} | {ri.item.test_case} ({ri.item.id}) | {sev} | {_remediation(ri.item.id)} |"
        )
    if not fails:
        lines.append("| — | No vulnerabilities found | — | — |")
    lines.append("")

    lines.append("## 6. Technical Findings\n")
    for tag, ri in zip(ds, fails, strict=True):
        sev = _SEV_TO_SCALE[severity_for(ri.item.id)]
        lines.append(f"### Finding {tag} — {ri.item.test_case} ({ri.item.id}) — {sev}")
        lines.append(f"- **WSTG ID:** {ri.item.id}    **ASVS:** {ri.item.asvs or '-'}")
        lines.append(f"- **Location:** {run.target}")
        lines.append(f"- **Description:** {ri.item.description}")
        lines.append(f"- **Evidence:** {'; '.join(ri.findings) or 'see checklist appendix'}")
        lines.append(f"- **Remediation:** {_remediation(ri.item.id)}\n")

    lines.append("## 7. Methodology Checklist (Appendix)\n")
    lines.append("| ID | Phase | Test Case | Mode | State |")
    lines.append("|---|---|---|---|---|")
    for ri in run.items:
        lines.append(
            f"| {ri.item.id} | {ri.item.phase} | {ri.item.test_case} "
            f"| {ri.item.mode.value} | {ri.state.value} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_summary_line(run: ChecklistRun) -> str:
    """A one-line console summary of the run."""
    c = run.counts
    return (
        f"{run.target}: {c[State.FAIL.value]} FAIL, {c[State.PASS.value]} PASS, "
        f"{c[State.TODO.value]} TODO, {c[State.NA.value]} N/A, {c[State.INFO.value]} INFO"
    )


def _fmt_item(ri: RunItem) -> str:  # small helper kept for reuse/tests
    return f"{ri.item.id} [{ri.state.value}] {ri.item.test_case}"
