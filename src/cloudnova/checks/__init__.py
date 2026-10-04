"""Built-in check modules.

Importing this package imports every check module, whose ``@register``
decorators populate the global registry. To add a rule pack, create a module
here and import it below, that is the entire wiring cost of a new check.

The terraform packs are split by what an attacker is after rather than by AWS
service, because that is how findings get triaged.
"""

from cloudnova.checks import (
    cloudformation,
    cloudtrail,
    iac_config,
    kubernetes,
    secrets,
    syslog,
    terraform,
    terraform_compute,
    terraform_data,
    terraform_network,
)

__all__ = [
    "cloudformation",
    "cloudtrail",
    "iac_config",
    "kubernetes",
    "secrets",
    "syslog",
    "terraform",
    "terraform_compute",
    "terraform_data",
    "terraform_network",
]
