"""Webhook alerting: formatting + delivery with an injected sender."""

from cloudnova import notify
from cloudnova.diff import ScanDiff


def _drift(n_new=2):
    intro = [{"check_id": f"C{i}", "title": f"issue {i}", "severity": "high"} for i in range(n_new)]
    return ScanDiff(introduced=intro, fixed=[], unchanged=1, old_score=10, new_score=40)


def test_format_drift_mentions_counts_and_score():
    text = notify.format_drift("app.example.com", _drift(2))
    assert "2 new finding" in text
    assert "10 -> 40" in text
    assert "C0" in text


def test_send_uses_injected_sender():
    sent = {}

    def fake(url, payload):
        sent["url"] = url
        sent["payload"] = payload
        return 200

    ok = notify.send("hello", url="https://hooks.example/x", sender=fake)
    assert ok is True
    assert sent["url"] == "https://hooks.example/x"
    assert b"hello" in sent["payload"]


def test_send_without_url_is_noop():
    assert notify.send("x", url=None, sender=lambda u, p: 200) is False


def test_notify_drift_only_when_new(monkeypatch):
    calls = {"n": 0}

    def fake(url, payload):
        calls["n"] += 1
        return 204

    # No new findings -> no send.
    empty = ScanDiff(introduced=[], fixed=[], unchanged=3)
    assert notify.notify_drift("t", empty, url="https://h/x", sender=fake) is False
    assert calls["n"] == 0
    # New findings -> send.
    assert notify.notify_drift("t", _drift(1), url="https://h/x", sender=fake) is True
    assert calls["n"] == 1


def test_webhook_url_from_env(monkeypatch):
    monkeypatch.setenv("CLOUDNOVA_SLACK_WEBHOOK", "https://hooks/env")
    assert notify.webhook_url() == "https://hooks/env"
    assert notify.webhook_url("https://explicit") == "https://explicit"
