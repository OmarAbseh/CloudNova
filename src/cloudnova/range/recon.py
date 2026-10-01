"""Organize reconnaissance output into a scope-checked service inventory.

The operator runs the tools (e.g. ``nmap -oX out.xml <in-scope target>``) on their
own machine; this ingests the result, verifies every discovered host against the
Range scope engine, and turns raw output into a structured inventory with
methodology next-steps per service. Hosts that aren't in scope are flagged and
excluded - the organizer never invents or contacts a target, it only structures
what the operator already collected, and refuses to surface anything unauthorized.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from xml.etree import ElementTree as ET

from cloudnova.range.scope import Scope

# Service name -> a methodology hint (what to look at next). Guidance, not exploits.
_SERVICE_HINTS: dict[str, str] = {
    "http": "Proxy through Burp; map endpoints; check OWASP Top 10 (see mentor topic web-owasp).",
    "https": "As http, plus review TLS config and certificate.",
    "ssh": "Note version; check default creds only if in scope; never brute-force blindly.",
    "ftp": "Check for anonymous login; note version for known-issue lookup.",
    "smb": "Enumerate shares/permissions (e.g. smbclient) - in scope only.",
    "mysql": "Note version; check exposure and default creds; should it be internet-facing?",
    "postgresql": "Note version; check exposure and authentication.",
    "rdp": "Note exposure; RDP to the internet is a common finding.",
    "dns": "Check for zone transfer; enumerate records.",
}


@dataclass(frozen=True)
class Service:
    port: int
    protocol: str
    name: str
    product: str = ""
    version: str = ""

    @property
    def hint(self) -> str:
        return _SERVICE_HINTS.get(self.name, "Note the version and research known issues.")


@dataclass
class Host:
    address: str
    in_scope: bool
    reason: str
    services: list[Service] = field(default_factory=list)


@dataclass
class ReconInventory:
    hosts: list[Host] = field(default_factory=list)
    skipped_out_of_scope: list[str] = field(default_factory=list)

    @property
    def in_scope_hosts(self) -> list[Host]:
        return [h for h in self.hosts if h.in_scope]


class ReconParseError(Exception):
    """Raised when recon output cannot be parsed."""


def parse_nmap_xml(xml_text: str) -> dict[str, list[Service]]:
    """Parse ``nmap -oX`` output into ``{host_address: [Service, ...]}``."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ReconParseError(f"Invalid nmap XML: {exc}") from exc

    hosts: dict[str, list[Service]] = {}
    for host_el in root.findall("host"):
        # Prefer IPv4/IPv6 address; fall back to the first address element.
        addr = ""
        for addr_el in host_el.findall("address"):
            addr = addr_el.get("addr", "")
            if addr_el.get("addrtype", "").startswith("ip"):
                break
        if not addr:
            continue
        services: list[Service] = []
        for port_el in host_el.findall("./ports/port"):
            state_el = port_el.find("state")
            if state_el is not None and state_el.get("state") != "open":
                continue
            svc_el = port_el.find("service")
            try:
                portid = int(port_el.get("portid", "0"))
            except ValueError:
                continue
            services.append(
                Service(
                    port=portid,
                    protocol=port_el.get("protocol", "tcp"),
                    name=(svc_el.get("name", "unknown") if svc_el is not None else "unknown"),
                    product=(svc_el.get("product", "") if svc_el is not None else ""),
                    version=(svc_el.get("version", "") if svc_el is not None else ""),
                )
            )
        hosts[addr] = services
    return hosts


def organize(xml_text: str, scope: Scope) -> ReconInventory:
    """Parse nmap XML and structure it, gating every host through the scope engine."""
    parsed = parse_nmap_xml(xml_text)
    inventory = ReconInventory()
    for address, services in sorted(parsed.items()):
        decision = scope.authorize(address)
        if not decision.allowed:
            inventory.skipped_out_of_scope.append(address)
            inventory.hosts.append(Host(address, in_scope=False, reason=decision.reason))
            continue
        inventory.hosts.append(
            Host(address, in_scope=True, reason=decision.reason, services=services)
        )
    return inventory
