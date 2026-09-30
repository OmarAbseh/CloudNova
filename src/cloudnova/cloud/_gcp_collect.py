"""Read-only GCP SDK collector. Isolated + lazy-imported so checks stay light.

Uses Application Default Credentials (gcloud auth / service account). Every call is
a list/get — nothing is created or modified. Each service is wrapped so partial
permissions still yield a partial inventory.
"""

from __future__ import annotations

import os

from cloudnova.cloud.gcp import CloudSqlInstance, FirewallRule, GcpInventory, GcsBucket


def collect(project: str | None = None) -> GcpInventory:
    proj = project or os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT")
    if not proj:
        raise RuntimeError("Set GOOGLE_CLOUD_PROJECT or pass --project.")
    inv = GcpInventory(project=proj)
    _collect_storage(proj, inv)
    _collect_firewalls(proj, inv)
    return inv


def _collect_storage(project: str, inv: GcpInventory) -> None:
    try:
        from google.cloud import storage

        client = storage.Client(project=project)
        for bucket in client.list_buckets():
            public = False
            try:
                policy = bucket.get_iam_policy(requested_policy_version=3)
                members = {m for binding in policy.bindings for m in binding.get("members", [])}
                public = bool(members & {"allUsers", "allAuthenticatedUsers"})
            except Exception:
                pass
            uniform = bool(
                getattr(bucket, "iam_configuration", {})
                .get("uniformBucketLevelAccess", {})
                .get("enabled", False)
            )
            inv.buckets.append(GcsBucket(name=bucket.name, public=public, uniform_access=uniform))
    except Exception:
        pass


def _collect_firewalls(project: str, inv: GcpInventory) -> None:
    try:
        from google.cloud import compute_v1

        client = compute_v1.FirewallsClient()
        for fw in client.list(project=project):
            if getattr(fw, "direction", "INGRESS") != "INGRESS":
                continue
            ranges = list(getattr(fw, "source_ranges", []) or [])
            rule = FirewallRule(name=fw.name)
            for allowed in getattr(fw, "allowed", []) or []:
                for pr in getattr(allowed, "ports", []) or ["0-65535"]:
                    lo, hi = _port_range(pr)
                    for cidr in ranges:
                        rule.world_ingress.append((lo, hi, cidr))
            if rule.world_ingress:
                inv.firewalls.append(rule)
    except Exception:
        pass


def _port_range(pr: str) -> tuple[int, int]:
    if "-" in pr:
        lo, hi = pr.split("-", 1)
        return int(lo), int(hi)
    try:
        p = int(pr)
        return p, p
    except ValueError:
        return 0, 65535


def _placeholder_sql(inv: GcpInventory) -> list[CloudSqlInstance]:
    # Cloud SQL Admin API listing is added when the sqladmin client is wired.
    return inv.sql
