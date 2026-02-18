"""Tests for clawcare.models."""

from clawcare.models import (
    AdapterInfo,
    ExtensionRoot,
    Finding,
    ScanResult,
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


class TestScanResult:
    def test_risk_score(self):
        result = ScanResult(
            scanned_path="/test",
            adapter=AdapterInfo(name="test", version="1.0"),
        )
        result.findings = [
            Finding("R1", Severity.CRITICAL, "a.py", 1, "", ""),
            Finding("R2", Severity.HIGH, "b.py", 2, "", ""),
        ]
        score = result.compute_risk_score()
        assert score == 35 + 20  # 55

    def test_risk_label(self):
        result = ScanResult(
            scanned_path="/test",
            adapter=AdapterInfo(name="test", version="1.0"),
        )
        result.risk_score = 0
        assert result.risk_label == "low"
        result.risk_score = 30
        assert result.risk_label == "medium"
        result.risk_score = 60
        assert result.risk_label == "high"
        result.risk_score = 80
        assert result.risk_label == "critical"

    def test_risk_score_caps_at_100(self):
        result = ScanResult(
            scanned_path="/test",
            adapter=AdapterInfo(name="test", version="1.0"),
        )
        result.findings = [
            Finding(f"R{i}", Severity.CRITICAL, "a.py", i, "", "")
            for i in range(10)
        ]
        score = result.compute_risk_score()
        assert score == 100
