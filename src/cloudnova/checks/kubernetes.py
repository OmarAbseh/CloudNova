"""Security checks for Kubernetes workloads.

These cover the highest-signal container misconfigurations: privileged
containers, host namespace sharing, running as root, privilege escalation, and
dangerous Linux capabilities. Each walks the pod template of a workload so it
applies uniformly to Pods, Deployments, DaemonSets, StatefulSets, and Jobs.
"""

from __future__ import annotations

from abc import abstractmethod
from collections.abc import Iterator
from typing import Any, ClassVar

from cloudnova.core.artifact import Artifact
from cloudnova.core.check import Check, register
from cloudnova.core.findings import Confidence, Finding, Location, Severity
from cloudnova.core.resource import CloudResource

#: Workload kinds that carry a pod template we should inspect.
_WORKLOAD_KINDS = {"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"}


def _resources(artifact: Artifact) -> list[CloudResource]:
    data = artifact.data
    return data if isinstance(data, list) else []


def _pod_spec(resource: CloudResource) -> dict[str, Any]:
    """Return the PodSpec regardless of workload kind.

    A bare Pod's spec is the pod spec; controllers nest it under
    ``spec.template.spec``; a CronJob nests it one level deeper still.
    """
    spec = resource.get("spec")
    if not isinstance(spec, dict):
        return {}
    if resource.type == "Pod":
        return spec
    if resource.type == "CronJob":
        job = _dig(spec, "jobTemplate", "spec", "template", "spec")
        return job if isinstance(job, dict) else {}
    template_spec = _dig(spec, "template", "spec")
    return template_spec if isinstance(template_spec, dict) else {}


def _dig(obj: Any, *keys: str) -> Any:
    for key in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _containers(pod_spec: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for field in ("initContainers", "containers", "ephemeralContainers"):
        value = pod_spec.get(field)
        if isinstance(value, list):
            out.extend(c for c in value if isinstance(c, dict))
    return out


class _K8sCheck(Check):
    """Base for Kubernetes checks: fixes target, filters to workloads."""

    target = "kubernetes"

    def run(self, artifact: Artifact) -> Iterator[Finding]:
        for resource in _resources(artifact):
            if resource.type in _WORKLOAD_KINDS:
                yield from self.check_workload(resource, _pod_spec(resource))

    @abstractmethod
    def check_workload(
        self, resource: CloudResource, pod_spec: dict[str, Any]
    ) -> Iterator[Finding]:
        """Yield findings for one workload and its (possibly empty) pod spec."""
        raise NotImplementedError

    def _loc(self, resource: CloudResource, container: str | None = None) -> Location:
        ns = resource.meta.get("namespace", "default")
        res = f"{ns}/{resource.type}/{resource.name}"
        if container:
            res += f"[{container}]"
        return Location(path=resource.path, resource=res)


@register
class PrivilegedContainer(_K8sCheck):
    id = "K8S_PRIVILEGED_CONTAINER"
    title = "Container runs in privileged mode"
    severity = Severity.CRITICAL

    def check_workload(
        self, resource: CloudResource, pod_spec: dict[str, Any]
    ) -> Iterator[Finding]:
        for container in _containers(pod_spec):
            sec = container.get("securityContext")
            if isinstance(sec, dict) and sec.get("privileged") is True:
                yield Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=self.severity,
                    confidence=Confidence.HIGH,
                    location=self._loc(resource, container.get("name")),
                    description=(
                        f"Container '{container.get('name')}' sets "
                        "securityContext.privileged: true, granting near-root access to the "
                        "host kernel — a container escape primitive."
                    ),
                    remediation="Remove privileged: true; grant only the specific capabilities "
                    "the workload needs.",
                    evidence="securityContext.privileged: true",
                    cis_controls=["CIS Kubernetes 5.2.1"],
                    mitre_attack=["T1611"],  # Escape to Host
                )


@register
class HostNamespaceSharing(_K8sCheck):
    id = "K8S_HOST_NAMESPACE"
    title = "Pod shares a host namespace"
    severity = Severity.HIGH

    _FIELDS: ClassVar[dict[str, str]] = {
        "hostNetwork": "network",
        "hostPID": "process",
        "hostIPC": "IPC",
    }

    def check_workload(
        self, resource: CloudResource, pod_spec: dict[str, Any]
    ) -> Iterator[Finding]:
        for field, human in self._FIELDS.items():
            if pod_spec.get(field) is True:
                yield Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=self.severity,
                    confidence=Confidence.HIGH,
                    location=self._loc(resource),
                    description=(
                        f"Pod sets {field}: true, sharing the host's {human} namespace and "
                        "weakening isolation between the container and the node."
                    ),
                    remediation=f"Remove {field}: true unless the workload genuinely requires "
                    "host namespace access.",
                    evidence=f"{field}: true",
                    cis_controls=["CIS Kubernetes 5.2.2"],
                    mitre_attack=["T1611"],
                )


@register
class RunAsRoot(_K8sCheck):
    id = "K8S_RUN_AS_ROOT"
    title = "Container may run as root"
    severity = Severity.MEDIUM

    def check_workload(
        self, resource: CloudResource, pod_spec: dict[str, Any]
    ) -> Iterator[Finding]:
        pod_sec = pod_spec.get("securityContext")
        pod_sec = pod_sec if isinstance(pod_sec, dict) else {}
        for container in _containers(pod_spec):
            sec = container.get("securityContext")
            sec = sec if isinstance(sec, dict) else {}
            # runAsNonRoot at container level overrides the pod default.
            non_root = sec.get("runAsNonRoot")
            if non_root is None:
                non_root = pod_sec.get("runAsNonRoot")
            run_as_user = sec.get("runAsUser", pod_sec.get("runAsUser"))
            if non_root is True or run_as_user not in (None, 0):
                continue
            yield Finding(
                check_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.MEDIUM,
                location=self._loc(resource, container.get("name")),
                description=(
                    f"Container '{container.get('name')}' does not set runAsNonRoot and has no "
                    "non-zero runAsUser, so it may run as UID 0 (root) inside the container."
                ),
                remediation="Set securityContext.runAsNonRoot: true and a non-zero runAsUser.",
                cis_controls=["CIS Kubernetes 5.2.6"],
                mitre_attack=["T1610"],  # Deploy Container
            )


@register
class PrivilegeEscalation(_K8sCheck):
    id = "K8S_ALLOW_PRIV_ESCALATION"
    title = "Container allows privilege escalation"
    severity = Severity.MEDIUM

    def check_workload(
        self, resource: CloudResource, pod_spec: dict[str, Any]
    ) -> Iterator[Finding]:
        for container in _containers(pod_spec):
            sec = container.get("securityContext")
            sec = sec if isinstance(sec, dict) else {}
            # Absent defaults to true in Kubernetes, so we flag anything not
            # explicitly disabled — at MEDIUM confidence when merely unset.
            value = sec.get("allowPrivilegeEscalation")
            if value is False:
                continue
            yield Finding(
                check_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.HIGH if value is True else Confidence.MEDIUM,
                location=self._loc(resource, container.get("name")),
                description=(
                    f"Container '{container.get('name')}' does not set "
                    "allowPrivilegeEscalation: false (defaults to true), letting a process gain "
                    "more privileges than its parent."
                ),
                remediation="Set securityContext.allowPrivilegeEscalation: false.",
                cis_controls=["CIS Kubernetes 5.2.5"],
                mitre_attack=["T1548"],  # Abuse Elevation Control Mechanism
            )


@register
class MissingResourceLimits(_K8sCheck):
    id = "K8S_NO_RESOURCE_LIMITS"
    title = "Container has no CPU/memory limits"
    severity = Severity.LOW

    def check_workload(
        self, resource: CloudResource, pod_spec: dict[str, Any]
    ) -> Iterator[Finding]:
        for container in _containers(pod_spec):
            resources = container.get("resources")
            limits = resources.get("limits") if isinstance(resources, dict) else None
            if not limits:
                yield Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=self.severity,
                    confidence=Confidence.HIGH,
                    location=self._loc(resource, container.get("name")),
                    description=(
                        f"Container '{container.get('name')}' declares no resources.limits, so a "
                        "runaway process can exhaust node CPU/memory (denial of service)."
                    ),
                    remediation="Set resources.limits.cpu and resources.limits.memory.",
                    cis_controls=["CIS Kubernetes 5.7.3"],
                    mitre_attack=["T1499"],  # Endpoint Denial of Service
                )


@register
class HostPathVolume(_K8sCheck):
    id = "K8S_HOSTPATH_VOLUME"
    title = "Pod mounts a hostPath volume"
    severity = Severity.HIGH

    def check_workload(
        self, resource: CloudResource, pod_spec: dict[str, Any]
    ) -> Iterator[Finding]:
        for volume in pod_spec.get("volumes", []) or []:
            if isinstance(volume, dict) and "hostPath" in volume:
                host_path = volume.get("hostPath", {})
                path = host_path.get("path") if isinstance(host_path, dict) else None
                yield Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=self.severity,
                    confidence=Confidence.HIGH,
                    location=self._loc(resource),
                    description=(
                        f"Volume '{volume.get('name')}' mounts host path '{path}'. A hostPath "
                        "exposes the node filesystem to the pod and can be used to escape to the "
                        "host."
                    ),
                    remediation="Avoid hostPath; use a PersistentVolumeClaim, configMap, or "
                    "emptyDir instead.",
                    evidence=f"hostPath.path: {path}",
                    cis_controls=["CIS Kubernetes 5.2.9"],
                    mitre_attack=["T1611"],
                )


@register
class MutableImageTag(_K8sCheck):
    id = "K8S_MUTABLE_IMAGE_TAG"
    title = "Container image uses a mutable tag"
    severity = Severity.LOW

    def check_workload(
        self, resource: CloudResource, pod_spec: dict[str, Any]
    ) -> Iterator[Finding]:
        for container in _containers(pod_spec):
            image = container.get("image")
            if not isinstance(image, str):
                continue
            # A digest (image@sha256:...) is immutable and safe.
            if "@sha256:" in image:
                continue
            tag = image.rsplit(":", 1)[1] if ":" in image.rsplit("/", 1)[-1] else "latest"
            if tag == "latest":
                yield Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=self.severity,
                    confidence=Confidence.MEDIUM,
                    location=self._loc(resource, container.get("name")),
                    description=(
                        f"Container '{container.get('name')}' uses image '{image}' with a mutable "
                        "'latest' tag, so deployments are not reproducible and a compromised tag "
                        "silently changes what runs."
                    ),
                    remediation=(
                        "Pin a specific version tag or, better, an immutable @sha256 digest."
                    ),
                    evidence=f"image: {image}",
                    cis_controls=["CIS Kubernetes 5.5.1"],
                    mitre_attack=["T1525"],  # Implant Internal Image
                )
