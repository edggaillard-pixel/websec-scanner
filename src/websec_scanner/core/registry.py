"""Check base class, decorator-based registry and auto-discovery.

Adding a detection module is deliberately a one-file operation: drop a module in
``websec_scanner/checks/``, subclass :class:`Check`, decorate it with
:func:`register`, and :func:`discover` will pick it up automatically.
"""

from __future__ import annotations

import importlib
import pkgutil
from abc import ABC, abstractmethod

from .context import ScanContext
from .models import Finding


class Check(ABC):
    """Base class for every detection module.

    Subclasses set the three class attributes and implement :meth:`run`.

    Attributes:
        id: Stable, unique identifier (used by ``--only``/``--skip`` and reports).
        name: Short human-readable name.
        description: One-line summary of what the check does.
    """

    id: str = ""
    name: str = ""
    description: str = ""

    @abstractmethod
    def run(self, ctx: ScanContext) -> list[Finding]:
        """Inspect the target in ``ctx`` and return a list of findings."""
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Check {self.id}>"


_REGISTRY: dict[str, type[Check]] = {}


def register(cls: type[Check]) -> type[Check]:
    """Class decorator that adds a :class:`Check` subclass to the registry."""
    if not cls.id:
        raise ValueError(f"Check {cls.__name__} must define a non-empty 'id'")
    if cls.id in _REGISTRY:
        raise ValueError(f"Duplicate check id: {cls.id!r}")
    _REGISTRY[cls.id] = cls
    return cls


def discover(package: str = "websec_scanner.checks") -> None:
    """Import every submodule of ``package`` so their checks self-register."""
    pkg = importlib.import_module(package)
    for mod in pkgutil.iter_modules(pkg.__path__):
        if not mod.name.startswith("_"):
            importlib.import_module(f"{package}.{mod.name}")


def get_checks(enabled: list[str] | None = None) -> list[Check]:
    """Instantiate registered checks, optionally filtered to ``enabled`` ids.

    Discovery is triggered lazily on first call.
    """
    if not _REGISTRY:
        discover()
    ids = enabled if enabled is not None else list(_REGISTRY)
    checks: list[Check] = []
    for cid in ids:
        cls = _REGISTRY.get(cid)
        if cls is not None:
            checks.append(cls())
    return checks


def registered_ids() -> list[str]:
    if not _REGISTRY:
        discover()
    return sorted(_REGISTRY)

# GROGNON
