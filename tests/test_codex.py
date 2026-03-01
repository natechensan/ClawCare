"""Tests for the Codex adapter — detection, discovery, and golden end-to-end."""

import os

import pytest

from clawcare.discovery import discover
from clawcare.gate import decide
from clawcare.integrations.codex import CodexAdapter
from clawcare.models import AdapterInfo, ScanResult, Severity
from clawcare.scanner.scanner import scan_root

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
adapter = CodexAdapter()


# ── Detection ────────────────────────────────────────────────────


class TestCodexDetect:
    def test_agents_md_detected(self):
        conf = adapter.detect(os.path.join(FIXTURES, "codex_project"))
        assert conf >= 0.5

    def test_malicious_project_detected(self):
        conf = adapter.detect(os.path.join(FIXTURES, "codex_malicious"))
        assert conf >= 0.5

    def test_override_boosts_confidence(self):
        conf = adapter.detect(os.path.join(FIXTURES, "codex_malicious"))
        # codex_malicious has AGENTS.md + AGENTS.override.md + skill
        assert conf >= 0.7

    def test_non_codex_low_confidence(self):
        # The benign_skill fixture has no AGENTS.md
        conf = adapter.detect(os.path.join(FIXTURES, "benign_skill"))
        # It has SKILL.md so might get some score, but no AGENTS.md
        # ClaudeCode / OpenClaw should win by priority
        assert conf < 0.5  # no AGENTS.md → low Codex signal


# ── Discovery ────────────────────────────────────────────────────


class TestCodexDiscover:
    def test_project_has_codex_project_root(self):
        roots = discover(adapter, os.path.join(FIXTURES, "codex_project"))
        kinds = {r.kind for r in roots}
        assert "codex_project" in kinds

    def test_project_discovers_skills(self):
        roots = discover(adapter, os.path.join(FIXTURES, "codex_project"))
        skill_roots = [r for r in roots if r.kind == "codex_skill"]
        assert len(skill_roots) >= 1

    def test_malicious_discovers_override_metadata(self):
        roots = discover(adapter, os.path.join(FIXTURES, "codex_malicious"))
        project_roots = [r for r in roots if r.kind == "codex_project"]
        assert len(project_roots) == 1
        assert project_roots[0].metadata.get("has_override") is True


# ── Golden: benign Codex project ─────────────────────────────────


class TestCodexBenignProject:
    def test_no_findings(self):
        target = os.path.join(FIXTURES, "codex_project")
        roots = discover(adapter, target)
        result = ScanResult(
            scanned_path=target,
            adapter=AdapterInfo(name=adapter.name),
            roots=roots,
            fail_on="high",
        )
        for root in roots:
            scope = adapter.scan_scope(root)
            result.findings.extend(scan_root(root, scope))

        assert len(result.findings) == 0

    def test_exits_zero_in_ci(self):
        target = os.path.join(FIXTURES, "codex_project")
        roots = discover(adapter, target)
        result = ScanResult(
            scanned_path=target,
            adapter=AdapterInfo(name=adapter.name),
            roots=roots,
            fail_on="high",
        )
        for root in roots:
            result.findings.extend(scan_root(root, adapter.scan_scope(root)))

        assert decide(result, ci_flag=True, fail_on="high") == 0


# ── Golden: malicious Codex project ──────────────────────────────


class TestCodexMaliciousProject:
    @pytest.fixture(autouse=True)
    def _scan(self):
        target = os.path.join(FIXTURES, "codex_malicious")
        roots = discover(adapter, target)
        self.result = ScanResult(
            scanned_path=target,
            adapter=AdapterInfo(name=adapter.name),
            roots=roots,
            fail_on="high",
        )
        for root in roots:
            scope = adapter.scan_scope(root)
            self.result.findings.extend(scan_root(root, scope))

    def test_has_critical_findings(self):
        severities = {f.severity for f in self.result.findings}
        assert Severity.CRITICAL in severities

    def test_has_high_findings(self):
        severities = {f.severity for f in self.result.findings}
        assert Severity.HIGH in severities

    def test_blocks_in_ci(self):
        code = decide(self.result, ci_flag=True, fail_on="high")
        assert code == 2

    def test_warns_locally(self):
        code = decide(self.result, ci_flag=False, fail_on="high")
        assert code == 0

    def test_scans_agents_md(self):
        """Ensure AGENTS.md content is scanned (pipe-to-shell in AGENTS.md)."""
        agents_findings = [f for f in self.result.findings if "AGENTS.md" in f.file_path]
        assert len(agents_findings) > 0

    def test_scans_override_file(self):
        """Ensure AGENTS.override.md is scanned too."""
        override_findings = [f for f in self.result.findings if "AGENTS.override.md" in f.file_path]
        assert len(override_findings) > 0
