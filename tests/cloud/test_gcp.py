"""GCP live-scan checks: pure, no SDK needed."""

from cloudnova.cloud.gcp import (
    CloudSqlInstance,
    FirewallRule,
    GcpInventory,
    GcsBucket,
    analyze_gcp,
    scan_gcp,
)
from cloudnova.core.findings import Severity


def _ids(findings):
    return {f.check_id for f in findings}


def test_public_bucket_is_critical():
    inv = GcpInventory(buckets=[GcsBucket("data", public=True, uniform_access=True)])
    findings = analyze_gcp(inv)
    assert findings and findings[0].check_id == "GCP_GCS_PUBLIC"
    assert findings[0].severity is Severity.CRITICAL


def test_hardened_bucket_clean():
    inv = GcpInventory(buckets=[GcsBucket("data", public=False, uniform_access=True)])
    assert analyze_gcp(inv) == []


def test_firewall_world_ssh_is_critical():
    inv = GcpInventory(firewalls=[FirewallRule("allow-ssh", world_ingress=[(22, 22, "0.0.0.0/0")])])
    findings = analyze_gcp(inv)
    assert findings and findings[0].check_id == "GCP_FIREWALL_WORLD_INGRESS"
    assert findings[0].severity is Severity.CRITICAL


def test_internal_firewall_not_flagged():
    inv = GcpInventory(firewalls=[FirewallRule("internal", world_ingress=[(22, 22, "10.0.0.0/8")])])
    assert analyze_gcp(inv) == []


def test_sql_public_and_no_ssl():
    inv = GcpInventory(sql=[CloudSqlInstance("db", public_ip=True, requires_ssl=False)])
    assert {"GCP_SQL_PUBLIC_IP", "GCP_SQL_NO_SSL"} <= _ids(analyze_gcp(inv))


def test_scan_gcp_accepts_injected_inventory():
    inv = GcpInventory(buckets=[GcsBucket("x", public=True)])
    assert _ids(scan_gcp(inventory=inv)) == {"GCP_GCS_PUBLIC"}
