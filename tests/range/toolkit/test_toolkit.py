"""Toolkit adapters: pure parsers + scope gating with an injected runner."""

from cloudnova.range.scope import Authorization, Scope
from cloudnova.range.toolkit import ffuf, nmap, nuclei
from cloudnova.range.toolkit.base import CommandResult

NMAP_XML = """<?xml version="1.0"?><nmaprun>
<host><address addr="10.0.0.5" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="8.2"/></port>
<port protocol="tcp" portid="8080"><state state="open"/>
<service name="http-proxy"/></port>
</ports></host></nmaprun>"""


def _scope(*hosts: str) -> Scope:
    auth = Authorization(program="t", authorized_by="me", acknowledged=True)
    return Scope(authorization=auth, in_scope=list(hosts), out_of_scope=[])


def _runner(stdout: str):
    calls = {"n": 0}

    def run(argv, timeout):
        calls["n"] += 1
        return CommandResult(returncode=0, stdout=stdout)

    run.calls = calls  # type: ignore[attr-defined]
    return run


def test_nmap_parse_flags_sensitive_port():
    findings = nmap.parse(NMAP_XML)
    ssh = next(f for f in findings if "22" in f.location.path)
    assert ssh.severity.value == "high"  # SSH is sensitive


def test_nmap_run_denies_out_of_scope():
    runner = _runner(NMAP_XML)
    result = nmap.run("10.9.9.9", _scope("10.0.0.5"), runner=runner)
    assert result.ran is False and "DENIED" in result.note
    assert runner.calls["n"] == 0  # never executed


def test_nmap_run_in_scope_with_injected_runner():
    result = nmap.run("10.0.0.5", _scope("10.0.0.5"), runner=_runner(NMAP_XML))
    assert result.ran is True
    assert any(f.check_id == "NMAP_OPEN_PORT" for f in result.findings)


def test_nuclei_parse_jsonl():
    line = (
        '{"template-id":"cve-2021-1234","matched-at":"https://t/x",'
        '"info":{"name":"Bad Thing","severity":"high","description":"boom"}}'
    )
    findings = nuclei.parse(line)
    assert findings and findings[0].severity.value == "high"
    assert "CVE_2021_1234" in findings[0].check_id


def test_ffuf_parse_json():
    data = '{"results":[{"url":"https://t/admin","status":200,"length":42}]}'
    findings = ffuf.parse(data)
    assert findings and findings[0].check_id == "FFUF_DISCOVERED_PATH"


def test_nuclei_scope_gate_blocks_run():
    runner = _runner("")
    result = nuclei.run("https://evil.com", _scope("good.com"), runner=runner)
    assert result.ran is False
    assert runner.calls["n"] == 0
