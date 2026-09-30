"""Azure live-scan checks: pure, no SDK needed."""

from cloudnova.cloud.azure import (
    AzureInventory,
    NetworkSecurityGroup,
    SqlServer,
    StorageAccount,
    analyze_azure,
    scan_azure,
)
from cloudnova.core.findings import Severity


def _ids(findings):
    return {f.check_id for f in findings}


def test_public_blob_and_http_and_unencrypted():
    inv = AzureInventory(
        storage_accounts=[
            StorageAccount("sa1", allow_blob_public_access=True, https_only=False, encrypted=False)
        ]
    )
    ids = _ids(analyze_azure(inv))
    assert {"AZ_STORAGE_PUBLIC_BLOB", "AZ_STORAGE_NO_HTTPS", "AZ_STORAGE_NO_ENCRYPTION"} <= ids


def test_hardened_storage_clean():
    inv = AzureInventory(
        storage_accounts=[
            StorageAccount("sa2", allow_blob_public_access=False, https_only=True, encrypted=True)
        ]
    )
    assert analyze_azure(inv) == []


def test_nsg_world_rdp_is_critical():
    inv = AzureInventory(
        nsgs=[NetworkSecurityGroup("nsg1", world_inbound=[("rdp", 3389, 3389, "*")])]
    )
    findings = analyze_azure(inv)
    assert findings and findings[0].check_id == "AZ_NSG_WORLD_INBOUND"
    assert findings[0].severity is Severity.CRITICAL


def test_nsg_internal_not_flagged():
    inv = AzureInventory(
        nsgs=[NetworkSecurityGroup("nsg2", world_inbound=[("ssh", 22, 22, "10.0.0.0/8")])]
    )
    assert analyze_azure(inv) == []


def test_sql_public_flagged():
    inv = AzureInventory(sql_servers=[SqlServer("sql1", public_network_access=True)])
    assert _ids(analyze_azure(inv)) == {"AZ_SQL_PUBLIC"}


def test_scan_azure_accepts_injected_inventory():
    inv = AzureInventory(sql_servers=[SqlServer("s", public_network_access=True)])
    assert _ids(scan_azure(inventory=inv)) == {"AZ_SQL_PUBLIC"}
