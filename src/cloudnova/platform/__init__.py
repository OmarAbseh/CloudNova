"""The Floatly Platform layer: identity, orgs, and org-scoped persistence.

Shared across Floatly products as *code*, not as a shared database — each
product deploys the same schema shape into its own project.
"""

from __future__ import annotations

from cloudnova.platform.client import AuthError, Session, SupabaseClient, SupabaseError
from cloudnova.platform.config import SupabaseConfig, load_config, service_role_key_present
from cloudnova.platform.tenancy import (
    ADMIN_ROLES,
    WRITE_ROLES,
    Invitation,
    Member,
    Org,
    accept_invitation,
    change_role,
    create_org,
    ensure_org,
    ensure_profile,
    invite_member,
    list_findings,
    list_invitations,
    list_members,
    list_my_invitations,
    list_orgs,
    list_scans,
    record_scan,
    remove_member,
    revoke_invitation,
)

__all__ = [
    "ADMIN_ROLES",
    "WRITE_ROLES",
    "AuthError",
    "Invitation",
    "Member",
    "Org",
    "Session",
    "SupabaseClient",
    "SupabaseConfig",
    "SupabaseError",
    "accept_invitation",
    "change_role",
    "create_org",
    "ensure_org",
    "ensure_profile",
    "invite_member",
    "list_findings",
    "list_invitations",
    "list_members",
    "list_my_invitations",
    "list_orgs",
    "list_scans",
    "load_config",
    "record_scan",
    "remove_member",
    "revoke_invitation",
    "service_role_key_present",
]
