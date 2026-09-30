"""Read-only Azure SDK collector. Isolated + lazy-imported so checks stay light.

Uses DefaultAzureCredential (env, managed identity, or `az login`). Every call is a
list/get — nothing is created or modified. Each service is wrapped so partial
permissions still yield a partial inventory.
"""

from __future__ import annotations

import os
from typing import Any

from cloudnova.cloud.azure import (
    AzureInventory,
    NetworkSecurityGroup,
    SqlServer,
    StorageAccount,
)


def collect(subscription_id: str | None = None) -> AzureInventory:
    from azure.identity import DefaultAzureCredential

    sub = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not sub:
        raise RuntimeError("Set AZURE_SUBSCRIPTION_ID or pass --subscription.")
    cred = DefaultAzureCredential()
    inv = AzureInventory(subscription=sub)
    _collect_storage(cred, sub, inv)
    _collect_network(cred, sub, inv)
    _collect_sql(cred, sub, inv)
    return inv


def _collect_storage(cred: Any, sub: str, inv: AzureInventory) -> None:
    try:
        from azure.mgmt.storage import StorageManagementClient

        client = StorageManagementClient(cred, sub)
        for acct in client.storage_accounts.list():
            inv.storage_accounts.append(
                StorageAccount(
                    name=acct.name,
                    allow_blob_public_access=bool(getattr(acct, "allow_blob_public_access", False)),
                    https_only=bool(getattr(acct, "enable_https_traffic_only", True)),
                    encrypted=getattr(acct, "encryption", None) is not None,
                )
            )
    except Exception:
        pass


def _collect_network(cred: Any, sub: str, inv: AzureInventory) -> None:
    try:
        from azure.mgmt.network import NetworkManagementClient

        client = NetworkManagementClient(cred, sub)
        for nsg in client.network_security_groups.list_all():
            group = NetworkSecurityGroup(name=nsg.name)
            for rule in nsg.security_rules or []:
                if getattr(rule, "direction", "") != "Inbound":
                    continue
                if getattr(rule, "access", "") != "Allow":
                    continue
                source = getattr(rule, "source_address_prefix", "") or ""
                prange = getattr(rule, "destination_port_range", "") or "0"
                lo, hi = _port_range(prange)
                group.world_inbound.append((rule.name, lo, hi, source))
            inv.nsgs.append(group)
    except Exception:
        pass


def _collect_sql(cred: Any, sub: str, inv: AzureInventory) -> None:
    try:
        from azure.mgmt.sql import SqlManagementClient

        client = SqlManagementClient(cred, sub)
        for srv in client.servers.list():
            inv.sql_servers.append(
                SqlServer(
                    name=srv.name,
                    public_network_access=str(getattr(srv, "public_network_access", "")).lower()
                    == "enabled",
                )
            )
    except Exception:
        pass


def _port_range(prange: str) -> tuple[int, int]:
    if prange == "*":
        return 0, 65535
    if "-" in prange:
        lo, hi = prange.split("-", 1)
        return int(lo), int(hi)
    try:
        p = int(prange)
        return p, p
    except ValueError:
        return 0, 65535
