"""The check plugin contract and registry.

A *check* is one security rule. Every check subclasses :class:`Check`, declares
metadata as class attributes, and implements :meth:`run`. The
:func:`register` decorator adds it to a global registry so the engine can
discover every rule without importing each one by hand — this is the plugin
architecture that lets the ruleset grow from 3 rules to 300 without touching
the engine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator

from cloudnova.core.artifact import Artifact
from cloudnova.core.findings import Finding, Severity


class Check(ABC):
    """Base class for every security rule.

    Subclasses set the class attributes (``id``, ``title``, ``severity``,
    ``target``) and implement :meth:`run`, which yields zero or more findings
    for a single parsed input. Checks must be pure and side-effect free: given
    the same input they return the same findings, which makes them trivially
    testable.
    """

    id: str
    title: str
    severity: Severity
    #: What kind of artifact this check consumes, e.g. "iac_config", "cloudtrail".
    target: str

    @abstractmethod
    def run(self, artifact: Artifact) -> Iterator[Finding]:
        """Yield findings for one parsed ``artifact`` of type ``self.target``."""
        raise NotImplementedError

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        # Fail loudly at import time if a subclass forgets required metadata,
        # rather than silently registering a half-defined rule.
        if ABC not in cls.__bases__:
            for attr in ("id", "title", "severity", "target"):
                if not hasattr(cls, attr):
                    raise TypeError(f"Check {cls.__name__} is missing required attribute '{attr}'")


class CheckRegistry:
    """Holds every registered check and lets the engine query by target."""

    def __init__(self) -> None:
        self._checks: dict[str, Check] = {}

    def add(self, check: Check) -> None:
        if check.id in self._checks:
            raise ValueError(f"Duplicate check id: {check.id!r}")
        self._checks[check.id] = check

    def all(self) -> Iterable[Check]:
        return tuple(self._checks.values())

    def for_target(self, target: str) -> list[Check]:
        return [c for c in self._checks.values() if c.target == target]

    def __len__(self) -> int:
        return len(self._checks)


#: Process-wide registry populated by the @register decorator at import time.
registry = CheckRegistry()


def register(check_cls: type[Check]) -> type[Check]:
    """Class decorator: instantiate a check and add it to the global registry."""
    registry.add(check_cls())
    return check_cls
