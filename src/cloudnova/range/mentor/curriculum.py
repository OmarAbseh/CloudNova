"""The Mentor's curriculum: a structured pentest learning path.

This is education content as data — a skill tree covering the penetration-testing
domain, each module mapped to the tools it uses, legitimate practice resources
(PortSwigger Web Security Academy, TryHackMe, HackTheBox, OWASP), the industry
certifications it counts toward, and the job level that expects it.

It is deliberately methodology- and learning-oriented (the same material CEH /
OSCP / PNPT teach): *how to think like a tester and how to use the tools*, pointed
at authorized and practice targets — never a copy-paste attack cookbook aimed at
arbitrary systems.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Level(StrEnum):
    """Career stage a module is expected at."""

    FOUNDATION = "foundation"
    JUNIOR = "junior"
    INTERMEDIATE = "intermediate"
    SENIOR = "senior"


@dataclass(frozen=True)
class Resource:
    """A legitimate place to learn/practice this skill."""

    name: str
    url: str
    kind: str  # "course", "lab", "reference", "practice-platform"


@dataclass(frozen=True)
class Module:
    """One skill area in the curriculum."""

    id: str
    title: str
    level: Level
    summary: str
    concepts: list[str]
    tools: list[str]
    resources: list[Resource]
    certs: list[str] = field(default_factory=list)
    prereqs: list[str] = field(default_factory=list)


# --- Legitimate, well-known learning platforms (referenced, not scraped) ---
_PORTSWIGGER = Resource(
    "PortSwigger Web Security Academy", "https://portswigger.net/web-security", "course"
)
_THM = Resource("TryHackMe", "https://tryhackme.com", "practice-platform")
_HTB = Resource("Hack The Box", "https://hackthebox.com", "practice-platform")
_OWASP_TOP10 = Resource("OWASP Top 10", "https://owasp.org/www-project-top-ten/", "reference")
_OWASP_WSTG = Resource(
    "OWASP Web Security Testing Guide",
    "https://owasp.org/www-project-web-security-testing-guide/",
    "reference",
)
_JUICE = Resource(
    "OWASP Juice Shop (local practice)", "https://owasp.org/www-project-juice-shop/", "lab"
)
_HACKTRICKS = Resource("HackTricks", "https://book.hacktricks.xyz", "reference")
_NIST = Resource(
    "NIST SP 800-115 (Technical Testing Guide)",
    "https://csrc.nist.gov/pubs/sp/800/115/final",
    "reference",
)


CURRICULUM: tuple[Module, ...] = (
    Module(
        id="foundations",
        title="Security & Networking Foundations",
        level=Level.FOUNDATION,
        summary="TCP/IP, HTTP, Linux, and the CIA triad — the groundwork everything builds on.",
        concepts=[
            "TCP/IP, ports, the OSI model, DNS",
            "HTTP/HTTPS requests, responses, status codes, headers, cookies",
            "Linux command line and file permissions",
            "The CIA triad (Confidentiality, Integrity, Availability) and threat modelling",
        ],
        tools=["bash", "curl", "netcat", "dig"],
        resources=[_THM, _NIST],
        certs=["CompTIA Security+", "eJPT"],
    ),
    Module(
        id="methodology",
        title="Pentest Methodology & Rules of Engagement",
        level=Level.FOUNDATION,
        summary="How an engagement is structured — and why scope and authorization come first.",
        concepts=[
            "Phases: recon → scanning → exploitation → post-exploitation → reporting",
            "Scope, rules of engagement, and written authorization (never test out of scope)",
            "Legal/ethical boundaries; responsible disclosure",
            "Note-taking and evidence collection from the very start",
        ],
        tools=["cloudnova range (scope engine)", "cherrytree", "obsidian"],
        resources=[_NIST, _OWASP_WSTG],
        certs=["eJPT", "PNPT", "CEH"],
        prereqs=["foundations"],
    ),
    Module(
        id="recon",
        title="Reconnaissance & OSINT",
        level=Level.JUNIOR,
        summary="Map the attack surface with passive and active recon before touching anything.",
        concepts=[
            "Passive vs active recon; OSINT sources",
            "Subdomain enumeration and DNS mapping",
            "Port and service discovery; service/version fingerprinting",
            "Turning recon into a prioritized target list (in-scope only)",
        ],
        tools=["nmap", "amass", "subfinder", "httpx", "whois"],
        resources=[_THM, _HACKTRICKS],
        certs=["eJPT", "PNPT", "OSCP"],
        prereqs=["methodology"],
    ),
    Module(
        id="burp-suite",
        title="Burp Suite Mastery",
        level=Level.JUNIOR,
        summary="The web tester's primary tool: intercept, inspect, modify, and replay HTTP.",
        concepts=[
            "Proxy: intercepting and inspecting traffic (set up the browser + CA cert)",
            "Repeater: modifying and replaying single requests to test behaviour",
            "Intruder: parameter fuzzing and automation concepts",
            "Decoder, Comparer, and using the scanner (Pro) responsibly",
        ],
        tools=["Burp Suite Community/Pro", "Firefox + FoxyProxy"],
        resources=[_PORTSWIGGER, _JUICE],
        certs=["eWPT", "OSCP", "CEH"],
        prereqs=["foundations"],
    ),
    Module(
        id="web-owasp",
        title="Web Application Testing (OWASP Top 10)",
        level=Level.JUNIOR,
        summary="Finding and understanding the most common web vulnerability classes.",
        concepts=[
            "Injection (SQLi, command injection) — cause, detection, impact, fix",
            "Broken access control & IDOR",
            "XSS (reflected/stored/DOM) and CSRF",
            "Authentication & session management flaws; SSRF",
        ],
        tools=["Burp Suite", "sqlmap", "ffuf"],
        resources=[_PORTSWIGGER, _OWASP_TOP10, _OWASP_WSTG, _JUICE],
        certs=["eWPT", "OSCP", "CEH"],
        prereqs=["burp-suite"],
    ),
    Module(
        id="network-traffic",
        title="Traffic Analysis with Wireshark",
        level=Level.JUNIOR,
        summary="Reading the wire: capturing and analysing packets to understand and troubleshoot.",
        concepts=[
            "Capturing traffic; capture vs display filters",
            "Following TCP/HTTP streams; spotting cleartext credentials",
            "Recognising common protocols and anomalies",
        ],
        tools=["Wireshark", "tshark", "tcpdump"],
        resources=[_THM],
        certs=["eJPT", "CompTIA Security+"],
        prereqs=["foundations"],
    ),
    Module(
        id="password-attacks",
        title="Password & Hash Attacks",
        level=Level.INTERMEDIATE,
        summary="How credentials are stored and how weak ones are recovered (concept + lab).",
        concepts=[
            "Hashing vs encryption; identifying hash types",
            "Dictionary, rule-based, and brute-force cracking (offline, on lab data)",
            "Wordlists and why password policy matters",
        ],
        tools=["hashcat", "john", "hashid"],
        resources=[_THM, _HACKTRICKS],
        certs=["OSCP", "PNPT"],
        prereqs=["foundations"],
    ),
    Module(
        id="privesc-linux",
        title="Linux Privilege Escalation",
        level=Level.INTERMEDIATE,
        summary="Going from a low-priv shell to root on a machine you're authorized to test.",
        concepts=[
            "Enumeration first: users, SUID binaries, cron jobs, capabilities, kernel version",
            "Common vectors: misconfigured sudo, writable paths, SUID abuse",
            "Using enumeration scripts to guide (not replace) your understanding",
        ],
        tools=["linpeas", "pspy", "GTFOBins (reference)"],
        resources=[_THM, _HACKTRICKS],
        certs=["OSCP", "PNPT"],
        prereqs=["recon"],
    ),
    Module(
        id="privesc-windows",
        title="Windows Privilege Escalation",
        level=Level.INTERMEDIATE,
        summary="Escalating on Windows hosts you're authorized to test.",
        concepts=[
            "Enumeration: privileges, services, unquoted paths, registry",
            "Common vectors: service misconfig, token privileges, DLL hijacking (concept)",
            "Mapping findings to remediation for the report",
        ],
        tools=["winpeas", "PowerUp", "Seatbelt"],
        resources=[_THM, _HACKTRICKS],
        certs=["OSCP", "PNPT"],
        prereqs=["recon"],
    ),
    Module(
        id="active-directory",
        title="Active Directory Attacks",
        level=Level.SENIOR,
        summary="Where most enterprise engagements live — enumeration and common attack paths.",
        concepts=[
            "AD structure: domains, OUs, GPOs, Kerberos",
            "Enumeration with BloodHound; attack paths as a graph",
            "Common techniques (Kerberoasting, etc.) at a methodology level, on lab domains",
        ],
        tools=["BloodHound", "CrackMapExec", "impacket"],
        resources=[_THM, _HTB, _HACKTRICKS],
        certs=["OSCP", "CRTP", "PNPT"],
        prereqs=["privesc-windows", "password-attacks"],
    ),
    Module(
        id="cloud-pentest",
        title="Cloud Penetration Testing",
        level=Level.SENIOR,
        summary="Testing AWS/Azure/GCP on accounts you own or are authorized to assess.",
        concepts=[
            "Cloud IAM and the shared-responsibility model",
            "Misconfiguration & privilege-escalation paths (see CloudNova's attack graph)",
            "Metadata service (IMDS) abuse concepts; over-permissive roles",
        ],
        tools=["cloudnova scan", "pacu", "ScoutSuite", "aws/az/gcloud CLIs"],
        resources=[_HACKTRICKS],
        certs=["CARTP", "AWS Security Specialty"],
        prereqs=["recon", "privesc-linux"],
    ),
    Module(
        id="reporting",
        title="Reporting & Communication",
        level=Level.JUNIOR,
        summary="The deliverable clients pay for. A great finding poorly written is worthless.",
        concepts=[
            "Structure: executive summary, methodology, findings, remediation, appendix",
            "Rating severity (CVSS) and writing clear reproduction steps",
            "Actionable remediation and business-risk framing",
            "CloudNova can draft findings in a consistent format",
        ],
        tools=["cloudnova (reporting)", "CVSS calculator", "markdown/LaTeX"],
        resources=[_NIST, _OWASP_WSTG],
        certs=["PNPT", "OSCP", "CEH"],
        prereqs=["methodology"],
    ),
)

_BY_ID = {m.id: m for m in CURRICULUM}


def get_module(module_id: str) -> Module | None:
    return _BY_ID.get(module_id)


def all_modules() -> tuple[Module, ...]:
    return CURRICULUM
