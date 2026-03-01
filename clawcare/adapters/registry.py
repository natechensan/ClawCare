"""Adapter registry — loading, registration, and selection."""

from __future__ import annotations

import importlib
import sys

from clawcare.adapters.base import Adapter


def _load_entry_point_adapters() -> list[Adapter]:
    """Load adapters registered via the ``clawcare.adapters`` entry-point group."""
    adapters: list[Adapter] = []
    if sys.version_info >= (3, 12):
        from importlib.metadata import entry_points

        eps = entry_points(group="clawcare.adapters")
    else:
        from importlib.metadata import entry_points as _ep

        all_eps = _ep()
        eps = (
            all_eps.get("clawcare.adapters", [])
            if isinstance(all_eps, dict)
            else all_eps.select(group="clawcare.adapters")
        )
    for ep in eps:
        try:
            cls = ep.load()
            adapters.append(cls() if isinstance(cls, type) else cls)
        except Exception:
            pass  # skip broken adapters silently
    return adapters


def load_import_adapter(import_string: str) -> Adapter:
    """Load an adapter from ``import:pkg.module:ClassName``.

    The *import_string* is the part after ``import:``.
    """
    module_path, class_name = import_string.rsplit(":", 1)
    mod = importlib.import_module(module_path)
    cls = getattr(mod, class_name)
    return cls() if isinstance(cls, type) else cls


def load_adapters(adapter_spec: str = "auto") -> list[Adapter]:
    """Return a list of candidate adapters for the given *adapter_spec*.

    ``auto``       — entry-point adapters
    ``<name>``     — entry-point adapters filtered to that name
    ``import:...`` — single adapter from import string
    """
    if adapter_spec.startswith("import:"):
        return [load_import_adapter(adapter_spec[len("import:") :])]

    all_adapters = _load_entry_point_adapters()

    if adapter_spec != "auto":
        matched = [a for a in all_adapters if a.name == adapter_spec]
        if not matched:
            raise ValueError(f"No registered adapter named '{adapter_spec}'")
        return matched

    return all_adapters


def select_adapter(
    adapters: list[Adapter],
    target_path: str,
) -> Adapter | None:
    """Pick the best adapter for *target_path* by confidence, with priority tie-break.

    Returns ``None`` if all confidences are 0.0.
    """
    scored: list[tuple[float, int, Adapter]] = []
    for a in adapters:
        conf = a.detect(target_path)
        if conf > 0.0:
            scored.append((conf, a.priority, a))

    if not scored:
        return None

    # highest confidence first, then highest priority
    scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
    return scored[0][2]


def list_registered_adapters() -> list[Adapter]:
    """Return all entry-point-registered adapters (for ``adapters list``)."""
    return _load_entry_point_adapters()
