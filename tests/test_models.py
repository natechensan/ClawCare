"""Tests for clawcare.models."""

from clawcare.models import (
    ExtensionRoot,
    Finding,
    Severity,
)


class TestSeverity:
    def test_ordering(self):
        assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL

    def test_from_str(self):
        assert Severity.from_str("high") == Severity.HIGH
        assert Severity.from_str("CRITICAL") == Severity.CRITICAL

    def test_str(self):
        assert str(Severity.LOW) == "low"


class TestExtensionRoot:
    def test_default_id(self):
        root = ExtensionRoot(root_path="/foo/bar")
        assert root.id == "foo_bar"

    def test_explicit_id(self):
        root = ExtensionRoot(root_path="/foo/bar", id="custom")
        assert root.id == "custom"


class TestFinding:
    def test_sort_key(self):
        f1 = Finding("R1", Severity.HIGH, "b.py", 10, "", "")
        f2 = Finding("R2", Severity.CRITICAL, "a.py", 5, "", "")
        f3 = Finding("R3", Severity.HIGH, "a.py", 1, "", "")
        ordered = sorted([f1, f2, f3], key=lambda f: f.sort_key())
        assert [f.rule_id for f in ordered] == ["R2", "R3", "R1"]
