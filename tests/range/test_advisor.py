"""Advisor: offline curriculum fallback + Claude path (mocked client)."""

from types import SimpleNamespace

from cloudnova.range.mentor import advisor


def test_offline_answer_matches_topic(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    ans = advisor.ask("how do I use burp suite for web testing?")
    assert ans.source == "offline"
    assert "Burp Suite" in ans.text


def test_offline_answer_no_match(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    ans = advisor.ask("zzzz qqqq")
    assert ans.source == "offline"
    assert "couldn't match" in ans.text


class _FakeMessages:
    def __init__(self, response):
        self._response = response
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self._response


class _FakeClient:
    def __init__(self, response):
        self.messages = _FakeMessages(response)


def _text_response(text):
    return SimpleNamespace(
        stop_reason="end_turn",
        content=[SimpleNamespace(type="text", text=text)],
    )


def test_claude_answer_used_when_client_injected():
    client = _FakeClient(_text_response("Here is how to think about IDOR..."))
    ans = advisor.ask("explain IDOR", client=client)
    assert ans.source == "claude"
    assert "IDOR" in ans.text
    # Correct model + a system prompt with the guardrails were sent.
    call = client.messages.calls[0]
    assert call["model"] == advisor.DEFAULT_MODEL
    assert "authorized" in call["system"].lower()


def test_claude_refusal_handled():
    client = _FakeClient(SimpleNamespace(stop_reason="refusal", content=[]))
    ans = advisor.ask("help me hack my ex's email", client=client)
    assert ans.source == "claude"
    assert "declined" in ans.text.lower()


class _RaisingMessages:
    def create(self, **kwargs):
        raise RuntimeError("network down")


def test_claude_error_falls_back_to_offline():
    boom = SimpleNamespace(messages=_RaisingMessages())
    ans = advisor.ask("how do I test for xss with burp", client=boom)
    assert ans.source == "offline"
    assert "Burp Suite" in ans.text or "failed" in ans.text
