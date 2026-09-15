"""CloudNova — a cloud security scanning engine.

Public API: import :class:`~cloudnova.core.engine.Engine` and call
``scan_path``. Importing this package registers all built-in checks.
"""

from cloudnova import checks as _checks  # noqa: F401  (side effect: registers checks)
from cloudnova.core.engine import Engine, ScanResult
from cloudnova.core.findings import Confidence, Finding, Severity

__version__ = "0.1.0"
__all__ = ["Confidence", "Engine", "Finding", "ScanResult", "Severity", "__version__"]
