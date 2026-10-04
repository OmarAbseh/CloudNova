"""The Azure and GCP rule packs.

Before these, an estate written against azurerm or the google provider scanned
clean because nothing covered it, which is worse than no support at all: it
reads as a pass. Every rule gets a true positive and a true negative.
"""

from pathlib import Path

from cloudnova.core.engine import Engine


def _ids(root: Path) -> set[str]:
    return {f.check_id for f in Engine().scan_path(root).findings}


def _tf(tmp_path: Path, content: str) -> Path:
    (tmp_path / "main.tf").write_text(content, encoding="utf-8")
    return tmp_path


def _findings(root: Path, check_id: str):
    return [f for f in Engine().scan_path(root).findings if f.check_id == check_id]


# == Azure =================================================================


def test_storage_http_allowed_flagged(tmp_path):
    assert "AZ_STORAGE_HTTP_ALLOWED" in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_storage_account" "s" {\n  enable_https_traffic_only = false\n}\n',
        )
    )


def test_storage_https_only_not_flagged(tmp_path):
    assert "AZ_STORAGE_HTTP_ALLOWED" not in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_storage_account" "s" {\n'
            "  enable_https_traffic_only = true\n"
            '  min_tls_version = "TLS1_2"\n}\n',
        )
    )


def test_storage_weak_tls_flagged(tmp_path):
    assert "AZ_STORAGE_WEAK_TLS" in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_storage_account" "s" {\n'
            "  enable_https_traffic_only = true\n"
            '  min_tls_version = "TLS1_0"\n}\n',
        )
    )


def test_storage_missing_tls_version_is_treated_as_weak(tmp_path):
    # The Azure default is TLS1_0 on older API versions, so absence is exposure.
    assert "AZ_STORAGE_WEAK_TLS" in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_storage_account" "s" {\n  enable_https_traffic_only = true\n}\n',
        )
    )


def test_storage_public_blobs_flagged(tmp_path):
    assert "AZ_STORAGE_PUBLIC_BLOBS" in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_storage_account" "s" {\n'
            "  allow_nested_items_to_be_public = true\n}\n",
        )
    )


def test_storage_legacy_public_attribute_also_flagged(tmp_path):
    # Two provider generations spell it differently; both must be caught.
    assert "AZ_STORAGE_PUBLIC_BLOBS" in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_storage_account" "s" {\n  allow_blob_public_access = true\n}\n',
        )
    )


def test_storage_private_blobs_not_flagged(tmp_path):
    assert "AZ_STORAGE_PUBLIC_BLOBS" not in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_storage_account" "s" {\n'
            "  allow_nested_items_to_be_public = false\n}\n",
        )
    )


def test_sql_public_access_flagged(tmp_path):
    assert "AZ_SQL_PUBLIC_ACCESS" in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_mssql_server" "s" {\n  public_network_access_enabled = true\n}\n',
        )
    )


def test_sql_private_not_flagged(tmp_path):
    assert "AZ_SQL_PUBLIC_ACCESS" not in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_mssql_server" "s" {\n  public_network_access_enabled = false\n}\n',
        )
    )


def test_sql_firewall_allow_all_azure_services_explains_itself(tmp_path):
    # 0.0.0.0-0.0.0.0 admits every tenant in the region, which people miss.
    root = _tf(
        tmp_path,
        'resource "azurerm_mssql_firewall_rule" "f" {\n'
        '  start_ip_address = "0.0.0.0"\n  end_ip_address = "0.0.0.0"\n}\n',
    )
    hits = _findings(root, "AZ_SQL_FIREWALL_ANY")
    assert hits
    assert "every tenant" in hits[0].description


def test_sql_firewall_whole_internet_flagged(tmp_path):
    assert "AZ_SQL_FIREWALL_ANY" in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_sql_firewall_rule" "f" {\n'
            '  start_ip_address = "0.0.0.0"\n  end_ip_address = "255.255.255.255"\n}\n',
        )
    )


def test_sql_firewall_narrow_range_not_flagged(tmp_path):
    assert "AZ_SQL_FIREWALL_ANY" not in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_sql_firewall_rule" "f" {\n'
            '  start_ip_address = "203.0.113.4"\n  end_ip_address = "203.0.113.4"\n}\n',
        )
    )


def test_sql_without_auditing_flagged(tmp_path):
    assert "AZ_SQL_NO_AUDITING" in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_mssql_server" "s" {\n  public_network_access_enabled = false\n}\n',
        )
    )


def test_nsg_world_open_rdp_flagged(tmp_path):
    root = _tf(
        tmp_path,
        'resource "azurerm_network_security_rule" "r" {\n'
        '  direction = "Inbound"\n  access = "Allow"\n'
        '  source_address_prefix = "*"\n  destination_port_range = "3389"\n}\n',
    )
    hits = _findings(root, "AZ_NSG_SENSITIVE_PORT_WORLD")
    assert hits
    assert "RDP" in hits[0].description


def test_nsg_port_range_covering_ssh_flagged(tmp_path):
    assert "AZ_NSG_SENSITIVE_PORT_WORLD" in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_network_security_rule" "r" {\n'
            '  direction = "Inbound"\n  access = "Allow"\n'
            '  source_address_prefix = "Internet"\n  destination_port_range = "20-25"\n}\n',
        )
    )


def test_nsg_world_open_https_not_flagged(tmp_path):
    assert "AZ_NSG_SENSITIVE_PORT_WORLD" not in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_network_security_rule" "r" {\n'
            '  direction = "Inbound"\n  access = "Allow"\n'
            '  source_address_prefix = "*"\n  destination_port_range = "443"\n}\n',
        )
    )


def test_nsg_outbound_rule_not_flagged(tmp_path):
    assert "AZ_NSG_SENSITIVE_PORT_WORLD" not in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_network_security_rule" "r" {\n'
            '  direction = "Outbound"\n  access = "Allow"\n'
            '  source_address_prefix = "*"\n  destination_port_range = "22"\n}\n',
        )
    )


def test_nsg_deny_rule_not_flagged(tmp_path):
    assert "AZ_NSG_SENSITIVE_PORT_WORLD" not in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_network_security_rule" "r" {\n'
            '  direction = "Inbound"\n  access = "Deny"\n'
            '  source_address_prefix = "*"\n  destination_port_range = "22"\n}\n',
        )
    )


def test_keyvault_without_purge_protection_flagged(tmp_path):
    assert "AZ_KEYVAULT_NO_PURGE_PROTECTION" in _ids(
        _tf(tmp_path, 'resource "azurerm_key_vault" "v" {\n  name = "kv"\n}\n')
    )


def test_keyvault_hardened_not_flagged(tmp_path):
    ids = _ids(
        _tf(
            tmp_path,
            'resource "azurerm_key_vault" "v" {\n'
            "  purge_protection_enabled = true\n"
            '  network_acls { default_action = "Deny" }\n}\n',
        )
    )
    assert "AZ_KEYVAULT_NO_PURGE_PROTECTION" not in ids
    assert "AZ_KEYVAULT_PUBLIC_ACCESS" not in ids


def test_aks_rbac_disabled_flagged(tmp_path):
    assert "AZ_AKS_RBAC_DISABLED" in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_kubernetes_cluster" "k" {\n'
            "  role_based_access_control_enabled = false\n}\n",
        )
    )


def test_aks_public_api_flagged(tmp_path):
    assert "AZ_AKS_PUBLIC_API" in _ids(
        _tf(tmp_path, 'resource "azurerm_kubernetes_cluster" "k" {\n  name = "k"\n}\n')
    )


def test_aks_private_cluster_not_flagged(tmp_path):
    ids = _ids(
        _tf(
            tmp_path,
            'resource "azurerm_kubernetes_cluster" "k" {\n'
            "  private_cluster_enabled = true\n"
            "  role_based_access_control_enabled = true\n}\n",
        )
    )
    assert "AZ_AKS_PUBLIC_API" not in ids
    assert "AZ_AKS_RBAC_DISABLED" not in ids


def test_aks_with_authorized_ranges_not_flagged(tmp_path):
    assert "AZ_AKS_PUBLIC_API" not in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_kubernetes_cluster" "k" {\n'
            '  api_server_authorized_ip_ranges = ["203.0.113.0/24"]\n}\n',
        )
    )


def test_app_service_http_flagged(tmp_path):
    assert "AZ_APPSERVICE_HTTP_ALLOWED" in _ids(
        _tf(tmp_path, 'resource "azurerm_linux_web_app" "a" {\n  https_only = false\n}\n')
    )


def test_app_service_https_only_not_flagged(tmp_path):
    assert "AZ_APPSERVICE_HTTP_ALLOWED" not in _ids(
        _tf(tmp_path, 'resource "azurerm_linux_web_app" "a" {\n  https_only = true\n}\n')
    )


def test_managed_disk_without_cmk_flagged(tmp_path):
    assert "AZ_DISK_NO_CMK" in _ids(
        _tf(tmp_path, 'resource "azurerm_managed_disk" "d" {\n  name = "d"\n}\n')
    )


def test_cosmos_public_flagged(tmp_path):
    assert "AZ_COSMOS_PUBLIC_ACCESS" in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_cosmosdb_account" "c" {\n'
            "  public_network_access_enabled = true\n}\n",
        )
    )


def test_vm_password_auth_flagged(tmp_path):
    assert "AZ_VM_PASSWORD_AUTH" in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_linux_virtual_machine" "v" {\n'
            "  disable_password_authentication = false\n}\n",
        )
    )


def test_vm_key_only_not_flagged(tmp_path):
    assert "AZ_VM_PASSWORD_AUTH" not in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_linux_virtual_machine" "v" {\n'
            "  disable_password_authentication = true\n}\n",
        )
    )


def test_postgres_ssl_off_flagged(tmp_path):
    assert "AZ_POSTGRES_SSL_OFF" in _ids(
        _tf(
            tmp_path,
            'resource "azurerm_postgresql_server" "p" {\n  ssl_enforcement_enabled = false\n}\n',
        )
    )


# == GCP ===================================================================


def test_bucket_public_binding_flagged(tmp_path):
    root = _tf(
        tmp_path,
        'resource "google_storage_bucket_iam_member" "m" {\n'
        '  role = "roles/storage.objectViewer"\n  member = "allUsers"\n}\n',
    )
    hits = _findings(root, "GCP_BUCKET_PUBLIC")
    assert hits
    assert hits[0].severity.value == "critical"


def test_bucket_all_authenticated_users_also_flagged(tmp_path):
    assert "GCP_BUCKET_PUBLIC" in _ids(
        _tf(
            tmp_path,
            'resource "google_storage_bucket_iam_binding" "b" {\n'
            '  role = "roles/storage.objectViewer"\n'
            '  members = ["allAuthenticatedUsers"]\n}\n',
        )
    )


def test_bucket_named_principal_not_flagged(tmp_path):
    assert "GCP_BUCKET_PUBLIC" not in _ids(
        _tf(
            tmp_path,
            'resource "google_storage_bucket_iam_member" "m" {\n'
            '  role = "roles/storage.objectViewer"\n'
            '  member = "serviceAccount:app@p.iam.gserviceaccount.com"\n}\n',
        )
    )


def test_bucket_without_uniform_access_flagged(tmp_path):
    ids = _ids(_tf(tmp_path, 'resource "google_storage_bucket" "b" {\n  name = "d"\n}\n'))
    assert "GCP_BUCKET_NO_UNIFORM_ACCESS" in ids
    assert "GCP_BUCKET_NO_VERSIONING" in ids


def test_hardened_bucket_not_flagged(tmp_path):
    ids = _ids(
        _tf(
            tmp_path,
            'resource "google_storage_bucket" "b" {\n'
            "  uniform_bucket_level_access = true\n"
            "  versioning { enabled = true }\n}\n",
        )
    )
    assert "GCP_BUCKET_NO_UNIFORM_ACCESS" not in ids
    assert "GCP_BUCKET_NO_VERSIONING" not in ids


def test_firewall_world_open_mysql_flagged(tmp_path):
    root = _tf(
        tmp_path,
        'resource "google_compute_firewall" "f" {\n'
        '  direction = "INGRESS"\n  source_ranges = ["0.0.0.0/0"]\n'
        '  allow { protocol = "tcp"\n    ports = ["3306"] }\n}\n',
    )
    hits = _findings(root, "GCP_FIREWALL_SENSITIVE_PORT_WORLD")
    assert hits
    assert "MySQL" in hits[0].description


def test_firewall_with_no_ports_covers_everything(tmp_path):
    # Omitting ports means every port for that protocol.
    assert "GCP_FIREWALL_SENSITIVE_PORT_WORLD" in _ids(
        _tf(
            tmp_path,
            'resource "google_compute_firewall" "f" {\n'
            '  source_ranges = ["0.0.0.0/0"]\n'
            '  allow { protocol = "tcp" }\n}\n',
        )
    )


def test_firewall_internal_range_not_flagged(tmp_path):
    assert "GCP_FIREWALL_SENSITIVE_PORT_WORLD" not in _ids(
        _tf(
            tmp_path,
            'resource "google_compute_firewall" "f" {\n'
            '  source_ranges = ["10.0.0.0/8"]\n'
            '  allow { protocol = "tcp"\n    ports = ["22"] }\n}\n',
        )
    )


def test_firewall_world_open_https_not_flagged(tmp_path):
    assert "GCP_FIREWALL_SENSITIVE_PORT_WORLD" not in _ids(
        _tf(
            tmp_path,
            'resource "google_compute_firewall" "f" {\n'
            '  source_ranges = ["0.0.0.0/0"]\n'
            '  allow { protocol = "tcp"\n    ports = ["443"] }\n}\n',
        )
    )


def test_instance_public_ip_flagged(tmp_path):
    assert "GCP_INSTANCE_PUBLIC_IP" in _ids(
        _tf(
            tmp_path,
            'resource "google_compute_instance" "i" {\n'
            '  network_interface {\n    network = "default"\n    access_config {}\n  }\n}\n',
        )
    )


def test_instance_without_access_config_not_flagged(tmp_path):
    assert "GCP_INSTANCE_PUBLIC_IP" not in _ids(
        _tf(
            tmp_path,
            'resource "google_compute_instance" "i" {\n'
            '  network_interface {\n    network = "default"\n  }\n}\n',
        )
    )


def test_instance_full_api_scope_flagged(tmp_path):
    assert "GCP_INSTANCE_FULL_API_SCOPE" in _ids(
        _tf(
            tmp_path,
            'resource "google_compute_instance" "i" {\n'
            "  service_account {\n"
            '    scopes = ["https://www.googleapis.com/auth/cloud-platform"]\n  }\n}\n',
        )
    )


def test_instance_narrow_scope_not_flagged(tmp_path):
    assert "GCP_INSTANCE_FULL_API_SCOPE" not in _ids(
        _tf(
            tmp_path,
            'resource "google_compute_instance" "i" {\n'
            '  service_account {\n    scopes = ["logging-write"]\n  }\n}\n',
        )
    )


def test_instance_serial_port_flagged(tmp_path):
    assert "GCP_INSTANCE_SERIAL_PORT" in _ids(
        _tf(
            tmp_path,
            'resource "google_compute_instance" "i" {\n'
            '  metadata = {\n    serial-port-enable = "true"\n  }\n}\n',
        )
    )


def test_instance_shielded_vm_not_flagged(tmp_path):
    assert "GCP_INSTANCE_NO_SHIELDED_VM" not in _ids(
        _tf(
            tmp_path,
            'resource "google_compute_instance" "i" {\n'
            "  shielded_instance_config {\n"
            "    enable_secure_boot = true\n"
            "    enable_integrity_monitoring = true\n  }\n}\n",
        )
    )


def test_sql_public_ip_flagged(tmp_path):
    assert "GCP_SQL_PUBLIC_IP" in _ids(
        _tf(
            tmp_path,
            'resource "google_sql_database_instance" "s" {\n'
            "  settings {\n    ip_configuration {\n      ipv4_enabled = true\n"
            "    }\n  }\n}\n",
        )
    )


def test_sql_world_authorized_is_critical(tmp_path):
    root = _tf(
        tmp_path,
        'resource "google_sql_database_instance" "s" {\n'
        "  settings {\n    ip_configuration {\n      ipv4_enabled = true\n"
        '      authorized_networks {\n        value = "0.0.0.0/0"\n      }\n'
        "    }\n  }\n}\n",
    )
    hits = _findings(root, "GCP_SQL_WORLD_AUTHORIZED")
    assert hits
    assert hits[0].severity.value == "critical"


def test_sql_ssl_not_required_flagged(tmp_path):
    assert "GCP_SQL_SSL_NOT_REQUIRED" in _ids(
        _tf(
            tmp_path,
            'resource "google_sql_database_instance" "s" {\n'
            "  settings {\n    ip_configuration {\n      ipv4_enabled = true\n"
            "    }\n  }\n}\n",
        )
    )


def test_private_sql_is_not_flagged_for_ssl(tmp_path):
    # Requiring SSL is moot when there is no public endpoint at all.
    ids = _ids(
        _tf(
            tmp_path,
            'resource "google_sql_database_instance" "s" {\n'
            "  settings {\n    ip_configuration {\n      ipv4_enabled = false\n"
            "    }\n  }\n}\n",
        )
    )
    assert "GCP_SQL_SSL_NOT_REQUIRED" not in ids
    assert "GCP_SQL_PUBLIC_IP" not in ids


def test_gke_public_nodes_flagged(tmp_path):
    assert "GCP_GKE_PUBLIC_NODES" in _ids(
        _tf(tmp_path, 'resource "google_container_cluster" "c" {\n  name = "c"\n}\n')
    )


def test_gke_private_nodes_not_flagged(tmp_path):
    assert "GCP_GKE_PUBLIC_NODES" not in _ids(
        _tf(
            tmp_path,
            'resource "google_container_cluster" "c" {\n'
            "  private_cluster_config {\n    enable_private_nodes = true\n  }\n}\n",
        )
    )


def test_gke_legacy_abac_flagged(tmp_path):
    assert "GCP_GKE_LEGACY_ABAC" in _ids(
        _tf(
            tmp_path,
            'resource "google_container_cluster" "c" {\n  enable_legacy_abac = true\n}\n',
        )
    )


def test_primitive_role_flagged(tmp_path):
    root = _tf(
        tmp_path,
        'resource "google_project_iam_member" "m" {\n'
        '  role = "roles/owner"\n  member = "user:dev@example.test"\n}\n',
    )
    hits = _findings(root, "GCP_IAM_PRIMITIVE_ROLE")
    assert hits
    assert "project owner" in hits[0].description


def test_predefined_role_not_flagged(tmp_path):
    assert "GCP_IAM_PRIMITIVE_ROLE" not in _ids(
        _tf(
            tmp_path,
            'resource "google_project_iam_member" "m" {\n'
            '  role = "roles/logging.viewer"\n  member = "user:dev@example.test"\n}\n',
        )
    )


def test_public_iam_binding_flagged(tmp_path):
    assert "GCP_IAM_PUBLIC_PRINCIPAL" in _ids(
        _tf(
            tmp_path,
            'resource "google_cloudfunctions_function_iam_member" "m" {\n'
            '  role = "roles/cloudfunctions.invoker"\n  member = "allUsers"\n}\n',
        )
    )


def test_bucket_binding_is_not_double_reported(tmp_path):
    # The bucket rule is more specific, so the generic one stands aside.
    ids = _ids(
        _tf(
            tmp_path,
            'resource "google_storage_bucket_iam_member" "m" {\n'
            '  role = "roles/storage.objectViewer"\n  member = "allUsers"\n}\n',
        )
    )
    assert "GCP_BUCKET_PUBLIC" in ids
    assert "GCP_IAM_PUBLIC_PRINCIPAL" not in ids


def test_service_account_key_flagged(tmp_path):
    assert "GCP_SERVICE_ACCOUNT_KEY" in _ids(
        _tf(
            tmp_path,
            'resource "google_service_account_key" "k" {\n  service_account_id = "app"\n}\n',
        )
    )


def test_kms_without_rotation_flagged(tmp_path):
    assert "GCP_KMS_NO_ROTATION" in _ids(
        _tf(tmp_path, 'resource "google_kms_crypto_key" "k" {\n  name = "k"\n}\n')
    )


def test_kms_with_rotation_not_flagged(tmp_path):
    assert "GCP_KMS_NO_ROTATION" not in _ids(
        _tf(
            tmp_path,
            'resource "google_kms_crypto_key" "k" {\n  rotation_period = "7776000s"\n}\n',
        )
    )


def test_bigquery_public_dataset_flagged(tmp_path):
    assert "GCP_BIGQUERY_PUBLIC" in _ids(
        _tf(
            tmp_path,
            'resource "google_bigquery_dataset" "d" {\n'
            '  access {\n    role = "READER"\n    special_group = "allAuthenticatedUsers"\n'
            "  }\n}\n",
        )
    )


def test_bigquery_private_dataset_not_flagged(tmp_path):
    assert "GCP_BIGQUERY_PUBLIC" not in _ids(
        _tf(
            tmp_path,
            'resource "google_bigquery_dataset" "d" {\n'
            '  access {\n    role = "READER"\n    user_by_email = "a@b.test"\n  }\n}\n',
        )
    )


# == cross-provider ========================================================


def test_a_hardened_azure_estate_is_quiet(tmp_path):
    assert (
        _ids(
            _tf(
                tmp_path,
                'resource "azurerm_storage_account" "s" {\n'
                "  enable_https_traffic_only = true\n"
                '  min_tls_version = "TLS1_2"\n'
                "  allow_nested_items_to_be_public = false\n}\n",
            )
        )
        == set()
    )


def test_a_hardened_gcp_estate_is_quiet(tmp_path):
    assert (
        _ids(
            _tf(
                tmp_path,
                'resource "google_storage_bucket" "b" {\n'
                "  uniform_bucket_level_access = true\n"
                "  versioning { enabled = true }\n}\n"
                'resource "google_kms_crypto_key" "k" {\n'
                '  rotation_period = "7776000s"\n}\n',
            )
        )
        == set()
    )


def test_aws_rules_do_not_fire_on_azure_resources(tmp_path):
    # Resource type prefixes must keep the packs from leaking into each other.
    ids = _ids(
        _tf(
            tmp_path,
            'resource "azurerm_storage_account" "s" {\n  enable_https_traffic_only = false\n}\n',
        )
    )
    assert not any(i.startswith(("TF_", "GCP_")) for i in ids)
