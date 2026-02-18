"""Discovery — call the adapter to find extension roots."""

from __future__ import annotations

from clawcare.adapters.base import Adapter
from clawcare.models import ExtensionRoot


def discover(adapter: Adapter, target_path: str) -> list[ExtensionRoot]:
    """Discover extension roots and return them in deterministic (sorted) order."""
    roots = adapter.discover_roots(target_path)
    roots.sort(key=lambda r: r.root_path)
    return roots
