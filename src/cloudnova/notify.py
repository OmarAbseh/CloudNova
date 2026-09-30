"""Notifications: alert on scan drift via an incoming webhook (Slack/Discord/etc.).

Wired into `cloudnova monitor` so continuous scanning can page a channel when new
findings appear. The HTTP send is injectable, so formatting and delivery logic are
tested offline without hitting the network. Configure with CLOUDNOVA_SLACK_WEBHOOK
(any Slack-compatible incoming-webhook URL).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

# A sender turns (url, json_bytes) into an HTTP status code. Injected for testing.
Sender = Callable[[str, bytes], int]


def _default_sender(url: str, payload: bytes) -> int:
    request = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except (urllib.error.URLError, OSError):
        return 0


def format_drift(target: str, drift: Any) -> str:
    """Human-readable alert text for a scan diff."""
    lines = [
        f"CloudNova: {len(drift.introduced)} new finding(s) on {target} "
        f"(score {drift.old_score} -> {drift.new_score}).",
    ]
    for f in drift.introduced[:10]:
        sev = str(f.get("severity", "")).upper()
        lines.append(f"- [{sev}] {f.get('check_id')}: {f.get('title')}")
    if len(drift.introduced) > 10:
        lines.append(f"...and {len(drift.introduced) - 10} more.")
    return "\n".join(lines)


def webhook_url(explicit: str | None = None) -> str | None:
    return explicit or os.environ.get("CLOUDNOVA_SLACK_WEBHOOK") or None


def send(text: str, *, url: str | None = None, sender: Sender | None = None) -> bool:
    """Post a message to the configured webhook. Returns True on a 2xx response."""
    target_url = webhook_url(url)
    if not target_url:
        return False
    payload = json.dumps({"text": text}).encode("utf-8")
    status = (sender or _default_sender)(target_url, payload)
    return 200 <= status < 300


def notify_drift(
    target: str, drift: Any, *, url: str | None = None, sender: Sender | None = None
) -> bool:
    """Send an alert if the diff introduced new findings. Returns True if sent."""
    if not getattr(drift, "introduced", None):
        return False
    return send(format_drift(target, drift), url=url, sender=sender)
