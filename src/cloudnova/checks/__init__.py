"""Built-in check modules.

Importing this package imports every check module, whose ``@register``
decorators populate the global registry. To add a rule pack, create a module
here and import it below — that is the entire wiring cost of a new check.
"""

from cloudnova.checks import cloudtrail, iac_config, syslog, terraform

__all__ = ["cloudtrail", "iac_config", "syslog", "terraform"]
