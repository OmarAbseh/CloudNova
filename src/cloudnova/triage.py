"""AI-assisted finding triage: explain a finding and propose a concrete fix.

The defensive-side counterpart to the mentor advisor. Given a finding, it produces
a plain-English explanation, why it matters from an attacker's view, and a concrete
remediation. With an Anthropic API key it uses Claude for a richer, tailored
answer; without one it falls back to a genuinely useful templated explanation built
from the finding's own fields and its MITRE ATT&CK mapping.

The ``anthropic`` package is optional (``pip install cloudnova[agent]``); importing
this module never requires it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

DEFAULT_MODEL = "claude-opus-5"

# Friendly names for the ATT&CK techniques used across the checks — turns a bare
# "T1530" into something a human immediately understands in the offline path.
_MITRE_NAMES: dict[str, str] = {
    "T1078": "Valid Accounts",
    "T1098": "Account Manipulation",
    "T1110": "Brute Force",
    "T1190": "Exploit Public-Facing Application",
    "T1499": "Endpoint Denial of Service",
    "T1525": "Implant Internal Image",
    "T1530": "Data from Cloud Storage",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1552": "Unsecured Credentials",
    "T1563": "Remote Service Session Hijacking",
    "T1610": "Deploy Container",
    "T1611": "Escape to Host",
}

_ATTACKER_VIEW: dict[str, str] = {
    "critical": "An attacker can exploit this directly for a serious compromise.",
    "high": "An attacker can use this to gain significant access or exposure.",
    "medium": "An attacker can leverage this as a useful step in a larger chain.",
    "low": "This weakens your posture and helps an attacker once they're in.",
    "info": "Informational — worth noting but not directly exploitable.",
}

_SYSTEM_PROMPT = """\
You are a cloud-security remediation expert. Given a single security finding, \
respond with three short sections, plain and practical for an engineer:
1. What it is — one or two sentences in plain English.
2. Why it matters — the attacker's-eye view of the impact.
3. How to fix it — concrete, specific steps (a config/IaC snippet if useful).
Be concise and actionable. Do not invent details not implied by the finding."""


@dataclass
class TriageNote:
    """A triaged explanation of one finding."""

    check_id: str
    title: str
    severity: str
    text: str
    source: str  # "claude" or "offline"


def _mitre_phrase(finding: dict[str, Any]) -> str:
    names = [
        f"{t} ({_MITRE_NAMES[t]})" if t in _MITRE_NAMES else t
        for t in finding.get("mitre_attack", [])
    ]
    return ", ".join(names)


def _offline_note(finding: dict[str, Any]) -> TriageNote:
    sev = str(finding.get("severity", "medium")).lower()
    lines = [
        f"What it is: {finding.get('description', finding.get('title', ''))}",
        f"Why it matters: {_ATTACKER_VIEW.get(sev, _ATTACKER_VIEW['medium'])}",
    ]
    mitre = _mitre_phrase(finding)
    if mitre:
        lines.append(f"  Technique: {mitre}.")
    lines.append(f"How to fix it: {finding.get('remediation', 'See the finding remediation.')}")
    if finding.get("references"):
        lines.append(f"Reference: {finding['references'][0]}")
    return TriageNote(
        check_id=str(finding.get("check_id", "")),
        title=str(finding.get("title", "")),
        severity=sev,
        text="\n".join(lines),
        source="offline",
    )


def _claude_note(finding: dict[str, Any], client: Any, model: str) -> TriageNote:
    import json

    prompt = "Finding (JSON):\n" + json.dumps(
        {
            k: finding.get(k)
            for k in (
                "check_id",
                "title",
                "severity",
                "description",
                "remediation",
                "evidence",
                "location",
                "cis_controls",
                "mitre_attack",
            )
        },
        indent=2,
        default=str,
    )
    try:
        response = client.messages.create(
            model=model,
            max_tokens=1200,
            thinking={"type": "adaptive"},
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as exc:
        note = _offline_note(finding)
        return TriageNote(
            note.check_id,
            note.title,
            note.severity,
            f"(Claude request failed: {exc})\n{note.text}",
            source="offline",
        )
    text = "".join(b.text for b in response.content if getattr(b, "type", None) == "text")
    return TriageNote(
        check_id=str(finding.get("check_id", "")),
        title=str(finding.get("title", "")),
        severity=str(finding.get("severity", "")).lower(),
        text=text or _offline_note(finding).text,
        source="claude",
    )


def explain_finding(
    finding: dict[str, Any], *, client: Any = None, model: str = DEFAULT_MODEL
) -> TriageNote:
    """Explain and propose a fix for one finding (Claude when available, else offline)."""
    if client is not None:
        return _claude_note(finding, client, model)
    from cloudnova.range.mentor.advisor import _credentials_available  # reuse the same check

    if not _credentials_available():
        return _offline_note(finding)
    try:
        import anthropic  # type: ignore[import-not-found]
    except ImportError:
        return _offline_note(finding)
    return _claude_note(finding, anthropic.Anthropic(), model)


def triage_findings(
    findings: list[dict[str, Any]],
    *,
    limit: int = 5,
    client: Any = None,
    model: str = DEFAULT_MODEL,
) -> list[TriageNote]:
    """Triage the top findings (already severity-sorted by the scan)."""
    return [explain_finding(f, client=client, model=model) for f in findings[:limit]]
