"""The advisor: a Claude-powered Q&A layer over the Mentor.

When an Anthropic API key (or `ant` profile) is available, questions are answered
by Claude with a security-tutor system prompt that keeps guidance
methodology-focused and authorized-targets-only. When no credential is present,
it falls back to an offline answer built from the curriculum — so the mentor is
useful with or without a key, and the offline path is fully testable.

The ``anthropic`` package is an optional dependency (``pip install
cloudnova[agent]``); importing this module never requires it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cloudnova.range.mentor.curriculum import all_modules

DEFAULT_MODEL = "claude-opus-5"

# The mentor persona + guardrails. Sent as the system prompt so Claude teaches
# like a tutor and stays on the right side of the line.
_SYSTEM_PROMPT = """\
You are CloudNova Mentor, an expert penetration-testing tutor helping a learner \
become a professional, ethical pentester.

Teach like a mentor: explain the concept, the methodology, and how to use the \
relevant tools (Burp Suite, Wireshark, nmap, etc.), with clear steps and pointers \
to legitimate practice resources (PortSwigger Web Security Academy, TryHackMe, \
HackTheBox, OWASP). Prefer teaching the learner to do it themselves over doing it \
for them.

Hard rules:
- Only ever guide testing of targets the learner is AUTHORIZED to test: their own \
labs, practice platforms, or an in-scope bug-bounty/engagement asset.
- If asked to help attack a system without authorization, refuse and redirect to \
an authorized practice equivalent.
- Keep guidance at a methodology and learning level; do not write turn-key attack \
payloads aimed at a specific real target.
- Emphasise scope, authorization, and note-taking — the habits of a professional.
"""


@dataclass
class Answer:
    """An advisor answer plus whether it came from the live model or offline."""

    text: str
    source: str  # "claude" or "offline"


def _credentials_available() -> bool:
    """True if an env-var credential is present.

    An `ant auth login` profile also counts, but detecting it precisely needs the
    CLI, so we treat env vars as the reliable signal and let a real call fall back.
    """
    import os

    return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))


def _offline_answer(question: str) -> Answer:
    """Answer from the curriculum when no model is available.

    Keyword-matches the question against module titles/concepts and returns the
    most relevant topics with their resources — genuinely useful, and it tells the
    user how to enable full Q&A.
    """
    q = question.lower()
    scored: list[tuple[int, Any]] = []
    for module in all_modules():
        haystay = " ".join([module.id, module.title, module.summary, *module.concepts]).lower()
        score = sum(1 for word in set(q.split()) if len(word) > 3 and word in haystay)
        if score:
            scored.append((score, module))
    scored.sort(key=lambda t: -t[0])

    lines = ["(offline answer — set ANTHROPIC_API_KEY for full Claude-powered Q&A)\n"]
    if not scored:
        lines.append(
            "I couldn't match that to a topic. Try `cloudnova range mentor path` to see "
            "the curriculum, or ask about a tool (burp, wireshark) or area (privesc, web)."
        )
        return Answer("\n".join(lines), source="offline")

    lines.append("Most relevant topics from your curriculum:\n")
    for _, module in scored[:3]:
        lines.append(f"• {module.title}  (mentor topic {module.id})")
        lines.append(f"    {module.summary}")
        if module.resources:
            r = module.resources[0]
            lines.append(f"    Start here: {r.name} — {r.url}")
    lines.append("\nRun `cloudnova range mentor topic <id>` for concepts, tools, and certs.")
    return Answer("\n".join(lines), source="offline")


def _claude_answer(question: str, client: Any, model: str) -> Answer:
    """Answer via the Anthropic API. ``client`` is an anthropic.Anthropic-like object."""
    try:
        response = client.messages.create(
            model=model,
            max_tokens=4000,
            thinking={"type": "adaptive"},
            output_config={"effort": "high"},
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": question}],
        )
    except Exception as exc:
        return Answer(
            f"(Claude request failed: {exc}) Falling back:\n\n{_offline_answer(question).text}",
            source="offline",
        )

    if getattr(response, "stop_reason", None) == "refusal":
        return Answer(
            "The mentor declined to answer that. If it's about an authorized or practice "
            "target, rephrase to make the authorization clear.",
            source="claude",
        )
    text = "".join(
        block.text for block in response.content if getattr(block, "type", None) == "text"
    )
    return Answer(text or "(no answer returned)", source="claude")


def ask(question: str, *, client: Any = None, model: str = DEFAULT_MODEL) -> Answer:
    """Ask the mentor a question.

    Uses Claude when a client is supplied or credentials are available; otherwise
    returns an offline curriculum-based answer. ``client`` is injectable for tests.
    """
    if client is not None:
        return _claude_answer(question, client, model)
    if not _credentials_available():
        return _offline_answer(question)
    try:
        import anthropic
    except ImportError:
        return Answer(
            "(install the agent extra for Claude-powered Q&A: pip install 'cloudnova[agent]')\n\n"
            + _offline_answer(question).text,
            source="offline",
        )
    return _claude_answer(question, anthropic.Anthropic(), model)
