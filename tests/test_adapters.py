"""Tests for adapter loading, selection, and listing."""

from __future__ import annotations

import pytest

from clawcare.adapters.registry import load_adapters, select_adapter
from clawcare.models import ExtensionRoot

# ── Fake adapters for testing ───────────────────────────────────

class FakeHighConfidence:
    name = "high_conf"
    version = "1.0"
    priority = 50

    def detect(self, target_path: str) -> float:
        return 0.9

    def discover_roots(self, target_path: str) -> list[ExtensionRoot]:
        return []

    def scan_scope(self, root: ExtensionRoot) -> dict:
        return {"include_globs": [], "exclude_globs": []}

    def default_manifest(self, root: ExtensionRoot) -> str | None:
        return None


class FakeLowConfidence:
    name = "low_conf"
    version = "1.0"
    priority = 100

    def detect(self, target_path: str) -> float:
        return 0.2

    def discover_roots(self, target_path: str) -> list[ExtensionRoot]:
        return []

    def scan_scope(self, root: ExtensionRoot) -> dict:
        return {"include_globs": [], "exclude_globs": []}

    def default_manifest(self, root: ExtensionRoot) -> str | None:
        return None


class FakeZeroConfidence:
    name = "zero"
    version = "1.0"
    priority = 200

    def detect(self, target_path: str) -> float:
        return 0.0

    def discover_roots(self, target_path: str) -> list[ExtensionRoot]:
        return []

    def scan_scope(self, root: ExtensionRoot) -> dict:
        return {"include_globs": [], "exclude_globs": []}

    def default_manifest(self, root: ExtensionRoot) -> str | None:
        return None


class FakeTiedConfidence:
    """Same confidence as FakeHighConfidence but lower priority."""
    name = "tied"
    version = "1.0"
    priority = 10

    def detect(self, target_path: str) -> float:
        return 0.9

    def discover_roots(self, target_path: str) -> list[ExtensionRoot]:
        return []

    def scan_scope(self, root: ExtensionRoot) -> dict:
        return {"include_globs": [], "exclude_globs": []}

    def default_manifest(self, root: ExtensionRoot) -> str | None:
        return None


# ── Tests ───────────────────────────────────────────────────────

class TestSelectAdapter:
    def test_picks_highest_confidence(self):
        adapters = [FakeLowConfidence(), FakeHighConfidence()]
        result = select_adapter(adapters, "/some/path")
        assert result is not None
        assert result.name == "high_conf"

    def test_priority_tiebreak(self):
        adapters = [FakeTiedConfidence(), FakeHighConfidence()]
        result = select_adapter(adapters, "/some/path")
        assert result is not None
        # Both have 0.9 confidence; FakeHighConfidence has priority 50 > 10
        assert result.name == "high_conf"

    def test_all_zero_returns_none(self):
        adapters = [FakeZeroConfidence()]
        result = select_adapter(adapters, "/some/path")
        assert result is None

    def test_empty_list_returns_none(self):
        result = select_adapter([], "/some/path")
        assert result is None


class TestLoadAdapters:
    def test_explicit_name_not_found_raises(self):
        with pytest.raises(ValueError, match="No registered adapter"):
            load_adapters("nonexistent_adapter_xyz")
