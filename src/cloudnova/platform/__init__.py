"""The Floatly Platform layer: identity, orgs, and org-scoped persistence.

Shared across Floatly products as *code*, not as a shared database — each
product deploys the same schema shape into its own project.
"""

from __future__ import annotations

from cloudnova.platform.client import AuthError, Session, SupabaseClient, SupabaseError
from cloudnova.platform.config import SupabaseConfig, load_config, service_role_key_present
from cloudnova.platform.tenancy import (
    Org,
    create_org,
    ensure_org,
    ensure_profile,
    list_findings,
    list_orgs,
    list_scans,
    record_scan,
)

__all__ = [
    "AuthError",
    "Org",
    "Session",
    "SupabaseClient",
    "SupabaseConfig",
    "SupabaseError",
    "create_org",
    "ensure_org",
    "ensure_profile",
    "list_findings",
    "list_orgs",
    "list_scans",
    "load_config",
    "record_scan",
    "service_role_key_present",
]
