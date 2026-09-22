"""Kubernetes check pack: positive + negative per rule, plus multi-doc handling."""

from pathlib import Path

from cloudnova.core.engine import Engine


def _ids(root: Path) -> set[str]:
    return {f.check_id for f in Engine().scan_path(root).findings}


def _write(tmp_path: Path, body: str) -> Path:
    (tmp_path / "manifest.yaml").write_text(body, encoding="utf-8")
    return tmp_path


_PRIVILEGED = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: app
          securityContext:
            privileged: true
"""

_HARDENED = """\
apiVersion: v1
kind: Pod
metadata:
  name: safe
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
    - name: app
      image: nginx:1.27.0
      securityContext:
        allowPrivilegeEscalation: false
        privileged: false
      resources:
        limits:
          cpu: "1"
          memory: 256Mi
"""


def test_privileged_container_critical(tmp_path):
    root = _write(tmp_path, _PRIVILEGED)
    findings = [
        f for f in Engine().scan_path(root).findings if f.check_id == "K8S_PRIVILEGED_CONTAINER"
    ]
    assert findings and findings[0].severity.value == "critical"


def test_hardened_pod_is_clean(tmp_path):
    root = _write(tmp_path, _HARDENED)
    assert Engine().scan_path(root).findings == []


def test_host_network_flagged(tmp_path):
    root = _write(
        tmp_path,
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"
        "spec:\n  hostNetwork: true\n  securityContext:\n    runAsNonRoot: true\n"
        "  containers:\n    - name: c\n      securityContext:\n"
        "        allowPrivilegeEscalation: false\n",
    )
    assert "K8S_HOST_NAMESPACE" in _ids(root)


def test_run_as_root_flagged_when_unset(tmp_path):
    root = _write(
        tmp_path,
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"
        "spec:\n  containers:\n    - name: c\n      image: nginx\n",
    )
    assert "K8S_RUN_AS_ROOT" in _ids(root)


def test_priv_escalation_flagged_when_unset(tmp_path):
    root = _write(
        tmp_path,
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"
        "spec:\n  containers:\n    - name: c\n      image: nginx\n",
    )
    assert "K8S_ALLOW_PRIV_ESCALATION" in _ids(root)


def test_cronjob_pod_spec_is_reached(tmp_path):
    root = _write(
        tmp_path,
        "apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: cj\n"
        "spec:\n  jobTemplate:\n    spec:\n      template:\n        spec:\n"
        "          containers:\n            - name: c\n"
        "              securityContext:\n                privileged: true\n",
    )
    assert "K8S_PRIVILEGED_CONTAINER" in _ids(root)


def test_multi_document_manifest_parses(tmp_path):
    root = _write(tmp_path, _PRIVILEGED + "---\n" + _HARDENED)
    result = Engine().scan_path(root)
    assert not result.errors
    # Two Pod-bearing docs: only the privileged one produces findings.
    assert "K8S_PRIVILEGED_CONTAINER" in {f.check_id for f in result.findings}


def test_non_k8s_yaml_not_treated_as_workload(tmp_path):
    root = _write(tmp_path, "access_control:\n  public: true\n")
    # Generic config, not Kubernetes -> no K8s findings (but iac_config fires).
    assert not any(i.startswith("K8S_") for i in _ids(root))


def test_hostpath_volume_flagged(tmp_path):
    root = _write(
        tmp_path,
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"
        "spec:\n  volumes:\n    - name: h\n      hostPath:\n        path: /\n"
        "  containers:\n    - name: c\n      image: nginx:1.2\n"
        "      securityContext:\n        runAsNonRoot: true\n"
        "        allowPrivilegeEscalation: false\n"
        '      resources:\n        limits:\n          cpu: "1"\n',
    )
    assert "K8S_HOSTPATH_VOLUME" in _ids(root)


def test_missing_resource_limits_flagged(tmp_path):
    root = _write(
        tmp_path,
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"
        "spec:\n  containers:\n    - name: c\n      image: nginx:1.2\n",
    )
    assert "K8S_NO_RESOURCE_LIMITS" in _ids(root)


def test_resource_limits_present_not_flagged(tmp_path):
    root = _write(
        tmp_path,
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"
        "spec:\n  containers:\n    - name: c\n      image: nginx:1.2\n"
        '      resources:\n        limits:\n          cpu: "1"\n          memory: 256Mi\n',
    )
    assert "K8S_NO_RESOURCE_LIMITS" not in _ids(root)


def test_latest_image_flagged(tmp_path):
    root = _write(
        tmp_path,
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"
        "spec:\n  containers:\n    - name: c\n      image: nginx:latest\n",
    )
    assert "K8S_MUTABLE_IMAGE_TAG" in _ids(root)


def test_pinned_image_digest_not_flagged(tmp_path):
    root = _write(
        tmp_path,
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"
        "spec:\n  containers:\n    - name: c\n      image: nginx@sha256:abc123\n"
        '      resources:\n        limits:\n          cpu: "1"\n',
    )
    assert "K8S_MUTABLE_IMAGE_TAG" not in _ids(root)
