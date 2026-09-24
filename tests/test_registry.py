"""The plugin registry must reject duplicate ids and expose the ruleset."""

import pytest

from cloudnova.core.check import CheckRegistry, registry
from cloudnova.core.findings import Severity


def test_builtin_checks_are_registered():
    ids = {c.id for c in registry.all()}
    assert {"IAC_ACCESS_PUBLIC", "CT_IAM_WILDCARD_ADMIN", "LOG_SSH_BRUTE_FORCE"} <= ids


def test_duplicate_id_rejected():
    class Dummy:
        id = "DUP"
        title = "t"
        severity = Severity.LOW
        target = "x"

    reg = CheckRegistry()
    reg.add(Dummy())
    with pytest.raises(ValueError, match="Duplicate"):
        reg.add(Dummy())


def test_for_target_filters():
    assert all(c.target == "cloudtrail" for c in registry.for_target("cloudtrail"))
