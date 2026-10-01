"""The blackbox web-application pentest checklist (PTES lifecycle + OWASP WSTG).

Transcribed from the standard methodology. Items flagged ``AUTO`` are checked
passively by CloudNova's web-assessment engine; ``MANUAL`` items are active or
context-dependent tests the operator performs, kept here with methodology
guidance so nothing is forgotten. The mentor (``cloudnova range mentor``) teaches
the manual techniques; the checklist tracks their status through the engagement.
"""

from __future__ import annotations

from cloudnova.range.checklist.model import ChecklistItem, Mode

A = Mode.AUTO
M = Mode.MANUAL
X = Mode.ACTIVE  # intrusive detection, opt-in

# fmt: off
_RAW: tuple[tuple[str, str, str, str, str, Mode, str], ...] = (
    # Phase 0, Asset Discovery & Triage
    ("PRE-001", "0: Asset Discovery", "Subdomain Enumeration (Passive)", "Passive discovery via Subfinder, Amass, crt.sh.", "Subfinder, Amass", M, ""),
    ("PRE-002", "0: Asset Discovery", "Subdomain Brute-Force (Active)", "Active subdomain guessing with a DNS wordlist.", "dnsx, puredns", M, ""),
    ("PRE-003", "0: Asset Discovery", "Live Host Filtering", "Filter which subdomains answer HTTP/HTTPS.", "httpx, httprobe", M, ""),
    ("PRE-004", "0: Asset Discovery", "Visual Inspection", "Screenshot targets to spot login panels.", "Aquatone, Gowitness", M, ""),
    ("PRE-005", "0: Asset Discovery", "Cloud Asset Discovery", "Investigate S3/Azure Blob/GCP storage of the target.", "cloud_enum", M, ""),
    # Phase 1, Information Gathering
    ("INFO-001", "1: Information Gathering", "Search Engine Discovery", "Google dorks for sensitive data / login panels.", "Google, Bing", M, "V1.1"),
    ("INFO-002", "1: Information Gathering", "Fingerprint Web Server", "Identify server type/version from HTTP banners.", "Wappalyzer, curl", A, "V1.9"),
    ("INFO-003", "1: Information Gathering", "Review Webserver Metafiles", "Inspect robots.txt, sitemap.xml, security.txt.", "curl", A, "V1.1"),
    ("INFO-004", "1: Information Gathering", "Enumerate Applications", "Other apps/ports on the server.", "Nmap, Masscan", M, "V1.1"),
    ("INFO-005", "1: Information Gathering", "Review Source Code Comments", "Look for dev notes/API keys in HTML/JS.", "manual, Burp", M, "V1.2"),
    ("INFO-007", "1: Information Gathering", "Map Execution Paths", "Map app flow (register->login->profile->pay).", "Burp Spider", M, ""),
    ("INFO-008", "1: Information Gathering", "Fingerprint Web Framework", "Identify framework/JS libs for CVE lookup.", "Wappalyzer", A, "V1.9"),
    ("INFO-010", "1: Information Gathering", "Map Application Architecture", "Detect WAF/load balancer/reverse proxy.", "wafw00f", M, "V1.5"),
    # Phase 2, Configuration & Deployment
    ("CONF-001", "2: Configuration & Deployment", "Network/Infrastructure Config", "Scan infra for known vulnerabilities.", "Nuclei, Nessus", M, "V14.2"),
    ("CONF-002", "2: Configuration & Deployment", "Test Application Platform", "Default pages/sample apps/admin panels open?", "dirb, ffuf", A, "V1.10"),
    ("CONF-004", "2: Configuration & Deployment", "Backup & Unreferenced Files", "Look for .bak/.old/.zip/.sql/.git.", "gobuster, ffuf", A, "V1.10"),
    ("CONF-005", "2: Configuration & Deployment", "Enumerate Admin Interfaces", "Access control on /admin, /dashboard, etc.", "ffuf", A, "V4.1"),
    ("CONF-006", "2: Configuration & Deployment", "Test HTTP Methods", "Unnecessary methods (PUT/DELETE/TRACE) enabled?", "curl, Burp", A, "V12.5"),
    ("CONF-007", "2: Configuration & Deployment", "HSTS Configuration", "Is Strict-Transport-Security present/correct?", "browser", A, "V9.1"),
    ("CONF-008", "2: Configuration & Deployment", "CORS Policy", "ACAO: * or null-origin vulnerability.", "Burp, curl", A, "V14.4"),
    ("CONF-009", "2: Configuration & Deployment", "Sensitive Data in Code", "Hardcoded API keys/creds in JS.", "TruffleHog", M, "V1.2"),
    # Phase 3, Authentication & Session
    ("ATHN-001", "3: Authentication", "Encrypted Transport", "Credentials sent over plaintext HTTP?", "Wireshark", A, "V2.1"),
    ("ATHN-002", "3: Authentication", "Default Credentials", "Try admin/admin on panels/CMS.", "manual", M, "V2.2"),
    ("ATHN-003", "3: Authentication", "Account Lockout / Throttling", "Lockout/CAPTCHA on brute force?", "Burp Intruder", M, "V2.2"),
    ("ATHN-004", "3: Authentication", "Authentication Bypass", "Forced browsing to internal pages.", "manual", M, "V4.1"),
    ("ATHN-005", "3: Authentication", "Remember Me Functionality", "Secure token vs simple cookie?", "Burp", M, "V2.5"),
    ("ATHN-006", "3: Authentication", "Browser Cache Weakness", "Back button loads page after logout?", "browser", M, ""),
    ("ATHN-009", "3: Authentication", "Account Enumeration", "'User not found' vs 'wrong password' differ?", "manual", M, "V2.1"),
    ("SESS-001", "3: Authentication", "Session Management Schema", "Predictable session IDs?", "Burp Sequencer", M, "V3.1"),
    ("SESS-002", "3: Authentication", "Cookie Attributes", "Secure/HttpOnly/SameSite on session cookies?", "browser", A, "V3.4"),
    ("SESS-003", "3: Authentication", "Session Fixation", "Cookie renewed after login?", "Burp", M, "V3.2"),
    # Phase 4, Authorization
    ("ATHZ-001", "4: Authorization", "Directory Traversal", "../../etc/passwd style payloads.", "Burp, DotDotPwn", X, "V5.5"),
    ("ATHZ-002", "4: Authorization", "Bypass Auth Schema", "Reach authorized pages by URL knowledge.", "manual", M, "V4.1"),
    ("ATHZ-003", "4: Authorization", "Privilege Escalation (Vertical)", "Call admin functions as a normal user.", "Burp AuthMatrix", M, "V4.2"),
    ("ATHZ-004", "4: Authorization", "IDOR (Horizontal)", "Change id=123 to id=124 to read others' data.", "Burp, Autorize", M, "V4.3"),
    # Phase 5, Input Validation & Exploitation
    ("INPV-001", "5: Input Validation", "Reflected XSS", "Reflect a benign marker in params to detect unencoded output.", "Dalfox", X, "V5.2"),
    ("INPV-002", "5: Input Validation", "Stored XSS", "Persistent JS in comments/profile fields.", "manual", M, "V5.2"),
    ("INPV-005", "5: Input Validation", "SQL Injection", "Detect DB errors from a breaking token in params.", "SQLMap", X, "V5.3"),
    ("INPV-011", "5: Input Validation", "Code Injection", "App executes PHP/Python (eval points)?", "manual", M, "V5.5"),
    ("INPV-012", "5: Input Validation", "OS Command Injection", "Inject ping / cat /etc/passwd.", "Commix", M, "V5.5"),
    ("INPV-006", "5: Input Validation", "SSRF", "Make the app call localhost / your server.", "Burp Collaborator", M, "V5.6"),
    ("INPV-008", "5: Input Validation", "XML Injection (XXE)", "External entities in XML fields.", "Burp", M, "V5.7"),
    ("BUSL-002", "5: Input Validation", "Business Logic / Price Manipulation", "Change amount/quantity in payment request.", "Burp Proxy", M, "V11.1"),
    ("BUSL-008", "5: Input Validation", "File Upload Testing", "Upload .php/.jsp/double-extension files.", "manual", M, "V12.1"),
    ("CLNT-009", "5: Input Validation", "Clickjacking", "Can the site run inside an iframe?", "manual", A, "V13.1"),
    ("CLNT-013", "5: Input Validation", "CSRF", "Anti-CSRF token on critical operations?", "Burp CSRF PoC", M, "V1.4"),
)
# fmt: on

BLACKBOX_CHECKLIST: tuple[ChecklistItem, ...] = tuple(
    ChecklistItem(
        id=r[0], phase=r[1], test_case=r[2], description=r[3], tools=r[4], mode=r[5], asvs=r[6]
    )
    for r in _RAW
)

# Well-known metafiles (INFO-003) and admin interfaces (CONF-005 / CONF-002).
METAFILES: tuple[str, ...] = ("robots.txt", "sitemap.xml", ".well-known/security.txt")
ADMIN_PATHS: tuple[str, ...] = (
    "admin",
    "admin/login",
    "administrator",
    "dashboard",
    "manage",
    "wp-admin",
    "phpmyadmin",
)


def phases() -> list[str]:
    """The checklist phases in order, de-duplicated."""
    seen: list[str] = []
    for item in BLACKBOX_CHECKLIST:
        if item.phase not in seen:
            seen.append(item.phase)
    return seen
