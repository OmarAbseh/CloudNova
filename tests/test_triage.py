"""Finding triage: offline templated explanation + Claude path (mocked)."""

from types import SimpleNamespace

from cloudnova import triage


def _finding(**over):
    base = {
        "check_id": "TF_S3_PUBLIC_ACL",
        "title": "S3 bucket grants a public ACL",
        "severity": "high",
        "description": "The bucket allows public-read.",
        "remediation": "Set acl=private and block public access.",
        "mitre_attack": ["T1530"],
        "references": ["https://example/s3"],
    }
    base.update(over)
    return base


def test_offline_note_has_three_parts(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    note = triage.explain_finding(_finding())
    assert note.source == "offline"
    assert "What it is:" in note.text
    assert "Why it matters:" in note.text
    assert "How to fix it:" in note.text


def test_offline_note_expands_mitre(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    note = triage.explain_finding(_finding())
    assert "Data from Cloud Storage" in note.text  # T1530 friendly name


def test_severity_drives_attacker_view(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    crit = triage.explain_finding(_finding(severity="critical"))
    assert "serious compromise" in crit.text


class _FakeClient:
    def __init__(self, text):
        self._text = text
        self.calls = []

    class _M:
        pass

    @property
    def messages(self):
        outer = self

        class M:
            def create(self, **kwargs):
                outer.calls.append(kwargs)
                return SimpleNamespace(
                    stop_reason="end_turn",
                    content=[SimpleNamespace(type="text", text=outer._text)],
                )

        return M()


def test_claude_path_used_when_client_injected():
    client = _FakeClient("What it is: ... How to fix it: ...")
    note = triage.explain_finding(_finding(), client=client)
    assert note.source == "claude"
    assert "How to fix" in note.text
    assert client.calls[0]["model"] == triage.DEFAULT_MODEL


def test_claude_error_falls_back_offline():
    class _Boom:
        messages = SimpleNamespace(create=lambda **k: (_ for _ in ()).throw(RuntimeError("x")))

    note = triage.explain_finding(_finding(), client=_Boom())
    assert note.source == "offline"
    assert "How to fix it:" in note.text


def test_triage_findings_respects_limit(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    findings = [_finding(check_id=f"C{i}") for i in range(10)]
    notes = triage.triage_findings(findings, limit=3)
    assert len(notes) == 3
