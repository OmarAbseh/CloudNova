"""Recon organizer: parse nmap XML, gate hosts through scope, structure services."""

import pytest

from cloudnova.range.recon import ReconParseError, organize, parse_nmap_xml
from cloudnova.range.scope import Authorization, Scope

_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="203.0.113.50" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/><service name="ssh" product="OpenSSH" version="8.2"/>
      </port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="443"><state state="closed"/><service name="https"/></port>
    </ports>
  </host>
  <host>
    <address addr="8.8.8.8" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="53"><state state="open"/><service name="dns"/></port>
    </ports>
  </host>
</nmaprun>
"""


def _scope():
    return Scope(
        authorization=Authorization("P", "policy", acknowledged=True),
        in_scope=["203.0.113.0/24"],
    )


def test_parse_only_open_ports():
    hosts = parse_nmap_xml(_XML)
    svc = hosts["203.0.113.50"]
    ports = {s.port for s in svc}
    assert ports == {22, 80}  # 443 is closed -> excluded


def test_organize_gates_out_of_scope_host():
    inv = organize(_XML, _scope())
    in_scope = {h.address for h in inv.in_scope_hosts}
    assert in_scope == {"203.0.113.50"}
    assert "8.8.8.8" in inv.skipped_out_of_scope


def test_service_hint_present():
    inv = organize(_XML, _scope())
    http = next(s for s in inv.in_scope_hosts[0].services if s.name == "http")
    assert "Burp" in http.hint


def test_out_of_scope_host_has_no_services_exposed():
    inv = organize(_XML, _scope())
    google = next(h for h in inv.hosts if h.address == "8.8.8.8")
    assert not google.in_scope
    assert google.services == []  # we don't surface services for unauthorized hosts


def test_invalid_xml_raises():
    with pytest.raises(ReconParseError):
        parse_nmap_xml("<not valid")


def test_unattested_scope_skips_everything():
    unattested = Scope(
        authorization=Authorization("", "", acknowledged=False), in_scope=["203.0.113.0/24"]
    )
    inv = organize(_XML, unattested)
    assert inv.in_scope_hosts == []
