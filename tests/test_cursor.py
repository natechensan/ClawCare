"""Tests for the Cursor adapter — detection, discovery, and golden end-to-end."""

import os

import pytest

from clawcare.discovery import discover
from clawcare.gate import decide
from clawcare.integrations.cursor import CursorAdapter
from clawcare.models import AdapterInfo, ScanResult, Severity
from clawcare.scanner.scanner import scan_root

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
adapter = CursorAdapter()


# ── Detection ────────────────────────────────────────────────────

class TestCursorDetect:
    def test_cursor_rules_detected(self):
        conf = adapter.detect(os.path.join(FIXTURES, "cursor_project"))
        assert conf >= 0.6

    def test_malicious_detected(self):
        conf = adapter.detect(os.path.join(FIXTURES, "cursor_malicious"))
        assert conf >= 0.6

    def test_legacy_cursorrules_boosts(self):
        # cursor_malicious has both .cursor/rules/ and .cursorrules
        conf = adapter.detect(os.path.join(FIXTURES, "cursor_malicious"))
        assert conf >= 0.8

    def test_non_cursor_low_confidence(self):
        # codex_project has no .cursor/ directory
        conf = adapter.detect(os.path.join(FIXTURES, "codex_project"))
        assert conf < 0.3


# ── Discovery ────────────────────────────────────────────────────

class TestCursorDiscover:
    def test_project_has_cursor_project_root(self):
        roots = discover(adapter, os.path.join(FIXTURES, "cursor_project"))
        kinds = {r.kind for r in roots}
        assert "cursor_project" in kinds

    def test_project_discovers_skills(self):
        roots = discover(adapter, os.path.join(FIXTURES, "cursor_project"))
        skill_roots = [r for r in roots if r.kind == "cursor_skill"]
        assert len(skill_roots) >= 1

    def test_project_metadata_has_rule_count(self):
        roots = discover(adapter, os.path.join(FIXTURES, "cursor_project"))
        project_roots = [r for r in roots if r.kind == "cursor_project"]
        assert project_roots[0].metadata.get("rule_count", 0) >= 2

    def test_malicious_has_legacy_cursorrules(self):
        roots = discover(adapter, os.path.join(FIXTURES, "cursor_malicious"))
        project_roots = [r for r in roots if r.kind == "cursor_project"]
        assert project_roots[0].metadata.get("has_legacy_cursorrules") is True


# ── Golden: benign Cursor project ────────────────────────────────

class TestCursorBenignProject:
    def test_no_findings(self):
        target = os.path.join(FIXTURES, "cursor_project")
        roots = discover(adapter, target)
        result = ScanResult(
            scanned_path=target,
            adapter=AdapterInfo(name=adapter.name, version=adapter.version),
            roots=roots,
            fail_on="high",
        )
        for root in roots:
            result.findings.extend(scan_root(root, adapter.scan_scope(root)))
        assert len(result.findings) == 0

    def test_exits_zero_in_ci(self):
        target = os.path.join(FIXTURES, "cursor_project")
        roots = discover(adapter, target)
        result = ScanResult(
            scanned_path=target,
            adapter=AdapterInfo(name=adapter.name, version=adapter.version),
            roots=roots,
            fail_on="high",
        )
        for root in roots:
            result.findings.extend(scan_root(root, adapter.scan_scope(root)))

        assert decide(result, ci_flag=True, fail_on="high") == 0


# ── Golden: malicious Cursor project ────────────────────────────

class TestCursorMaliciousProject:
    @pytest.fixture(autouse=True)
    def _scan(self):
        target = os.path.join(FIXTURES, "cursor_malicious")
        roots = discover(adapter, target)
        self.result = ScanResult(
            scanned_path=target,
            adapter=AdapterInfo(name=adapter.name, version=adapter.version),
            roots=roots,
            fail_on="high",
        )
        for root in roots:
            self.result.findings.extend(
                scan_root(root, adapter.scan_scope(root)))


    def test_has_critical_findings(self):
        assert Severity.CRITICAL in {f.severity for f in self.result.findings}

    def test_has_high_findings(self):
        assert Severity.HIGH in {f.severity for f in self.result.findings}

    def test_blocks_in_ci(self):
        assert decide(self.result, ci_flag=True, fail_on="high") == 2

    def test_warns_locally(self):
        assert decide(self.result, ci_flag=False, fail_on="high") == 0

    def test_scans_mdc_files(self):
        """Ensure .mdc rule files are scanned."""
        mdc_findings = [
            f for f in self.result.findings if ".mdc" in f.file_path
        ]
        assert len(mdc_findings) > 0

    def test_scans_legacy_cursorrules(self):
        """Ensure .cursorrules is scanned."""
        legacy_findings = [
            f for f in self.result.findings if ".cursorrules" in f.file_path
        ]
        assert len(legacy_findings) > 0
