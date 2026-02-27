"""Adapter protocol — the stable contract every adapter must satisfy."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from clawcare.models import ExtensionRoot


@runtime_checkable
class Adapter(Protocol):
    """Pluggable adapter contract (§6.3 of design doc)."""

    name: str
    priority: int  # tie-break for auto-detect; higher wins

    def detect(self, target_path: str) -> float:
        """Return confidence 0.0–1.0 that this adapter applies.

        Must be fast and side-effect free.
        """
        ...

    def discover_roots(self, target_path: str) -> list[ExtensionRoot]:
        """Return discovered extension roots under *target_path*."""
        ...

    def scan_scope(self, root: ExtensionRoot) -> dict:
        """Return scan scope for *root*.

        Expected keys:
            include_globs: list[str]
            exclude_globs: list[str]
            max_file_size_kb: int  (optional override)
            languages: list[str]   (optional hints)
        """
        ...

    def default_manifest(self, root: ExtensionRoot) -> str | None:
        """Return manifest path if adapter has conventions; else None."""
        ...
