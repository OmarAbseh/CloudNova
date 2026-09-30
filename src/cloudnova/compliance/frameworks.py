"""Compliance frameworks and the mapping from CloudNova checks to their controls.

Findings are classified into a small set of security *categories* (exposure,
encryption, identity, logging, secrets), and each category maps to the relevant
controls in each framework. Classifying by category rather than by individual
check id means new checks are covered automatically as long as their id follows
the naming convention.
"""

from __future__ import annotations

from enum import StrEnum


class Framework(StrEnum):
    ISO_27001 = "iso27001"
    NIST_CSF = "nist"
    PCI_DSS = "pci"


class Category(StrEnum):
    EXPOSURE = "exposure"  # public access, world-open network
    ENCRYPTION = "encryption"  # at rest / in transit
    IDENTITY = "identity"  # IAM, MFA, keys, passwords, privilege
    LOGGING = "logging"  # audit logging / monitoring
    SECRETS = "secrets"  # hard-coded credentials
    OTHER = "other"


# Control catalogs (curated, human-readable subsets of each framework).
CATALOGS: dict[Framework, dict[str, str]] = {
    Framework.ISO_27001: {
        "A.5.15": "Access control",
        "A.5.16": "Identity management",
        "A.5.17": "Authentication information",
        "A.8.5": "Secure authentication",
        "A.8.15": "Logging",
        "A.8.16": "Monitoring activities",
        "A.8.20": "Networks security",
        "A.8.22": "Segregation of networks",
        "A.8.24": "Use of cryptography",
    },
    Framework.NIST_CSF: {
        "PR.AC-1": "Identities and credentials are managed",
        "PR.AC-4": "Access permissions follow least privilege",
        "PR.AC-5": "Network integrity is protected",
        "PR.DS-1": "Data-at-rest is protected",
        "PR.DS-2": "Data-in-transit is protected",
        "PR.PT-1": "Audit/log records are determined and reviewed",
        "DE.AE-3": "Event data are collected and correlated",
    },
    Framework.PCI_DSS: {
        "Req.1": "Install and maintain network security controls",
        "Req.3": "Protect stored account data",
        "Req.4": "Protect data in transit with strong cryptography",
        "Req.7": "Restrict access by business need-to-know",
        "Req.8": "Identify users and authenticate access",
        "Req.10": "Log and monitor all access",
    },
}

# category -> controls it touches, per framework.
CATEGORY_CONTROLS: dict[Framework, dict[Category, list[str]]] = {
    Framework.ISO_27001: {
        Category.EXPOSURE: ["A.8.20", "A.8.22", "A.5.15"],
        Category.ENCRYPTION: ["A.8.24"],
        Category.IDENTITY: ["A.5.15", "A.5.16", "A.8.5"],
        Category.LOGGING: ["A.8.15", "A.8.16"],
        Category.SECRETS: ["A.5.17", "A.8.24"],
    },
    Framework.NIST_CSF: {
        Category.EXPOSURE: ["PR.AC-5"],
        Category.ENCRYPTION: ["PR.DS-1", "PR.DS-2"],
        Category.IDENTITY: ["PR.AC-1", "PR.AC-4"],
        Category.LOGGING: ["PR.PT-1", "DE.AE-3"],
        Category.SECRETS: ["PR.AC-1", "PR.DS-1"],
    },
    Framework.PCI_DSS: {
        Category.EXPOSURE: ["Req.1"],
        Category.ENCRYPTION: ["Req.3", "Req.4"],
        Category.IDENTITY: ["Req.7", "Req.8"],
        Category.LOGGING: ["Req.10"],
        Category.SECRETS: ["Req.3", "Req.8"],
    },
}


def categorize(check_id: str) -> Category:
    """Classify a check id into a security category by its name."""
    cid = check_id.upper()
    if any(k in cid for k in ("SECRET", "CREDENTIAL", "TOKEN", "HARDCODED")):
        return Category.SECRETS
    if any(
        k in cid for k in ("PUBLIC", "WORLD", "ANON", "INGRESS", "_SG_", "NSG", "ACCESS_PUBLIC")
    ):
        return Category.EXPOSURE
    if any(k in cid for k in ("ENCRYPT", "KMS", "TLS", "HTTPS", "NO_TLS", "SSL")):
        return Category.ENCRYPTION
    if any(k in cid for k in ("IAM", "MFA", "WILDCARD", "PRIVILEGE", "KEY", "PASSWORD", "AUTH")):
        return Category.IDENTITY
    if any(k in cid for k in ("LOG", "CLOUDTRAIL", "AUDIT", "MONITOR")):
        return Category.LOGGING
    return Category.OTHER
