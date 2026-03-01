"""Tests for gate mode logic (§9)."""

import pytest

from clawcare.gate import decide
from clawcare.models import AdapterInfo, Finding, ScanResult, Severity


@pytest.fixture
def result_with_high():
    r = ScanResult(
        scanned_path="/test",
        adapter=AdapterInfo(name="test"),
    )
    r.findings = [
        Finding("R1", Severity.HIGH, "a.py", 1, "", "high finding"),
    ]
    return r


@pytest.fixture
def result_with_medium():
    r = ScanResult(
        scanned_path="/test",
        adapter=AdapterInfo(name="test"),
    )
    r.findings = [
        Finding("R1", Severity.MEDIUM, "a.py", 1, "", "medium finding"),
    ]
    return r


@pytest.fixture
def result_clean():
    return ScanResult(
        scanned_path="/test",
        adapter=AdapterInfo(name="test"),
    )


class TestGateDecide:
    def test_local_always_exits_0(self, result_with_high, monkeypatch):
        monkeypatch.delenv("CI", raising=False)
        code = decide(result_with_high, ci_flag=False, enforce=False)
        assert code == 0

    def test_ci_blocks_on_high(self, result_with_high):
        code = decide(result_with_high, ci_flag=True, fail_on="high")
        assert code == 2

    def test_ci_passes_below_threshold(self, result_with_medium):
        code = decide(result_with_medium, ci_flag=True, fail_on="high")
        assert code == 0

    def test_ci_blocks_medium_when_threshold_medium(self, result_with_medium):
        code = decide(result_with_medium, ci_flag=True, fail_on="medium")
        assert code == 2

    def test_enforce_blocks_locally(self, result_with_high):
        code = decide(result_with_high, ci_flag=False, enforce=True, fail_on="high")
        assert code == 2

    def test_clean_scan_passes_in_ci(self, result_clean):
        code = decide(result_clean, ci_flag=True, fail_on="high")
        assert code == 0

    def test_ci_env_var(self, result_with_high, monkeypatch):
        monkeypatch.setenv("CI", "true")
        code = decide(result_with_high, ci_flag=False, fail_on="high")
        assert code == 2
