"""Tests for scan scope — verifies each adapter only scans extension files,
not project-level files like README.md, CI configs, or application code.

These tests guard against the regression where the scanner would scan the
entire project tree, causing false positives on non-extension files.
"""

import os

from clawcare.discovery import discover
from clawcare.integrations.claude_code import ClaudeCodeAdapter
from clawcare.integrations.codex import CodexAdapter
from clawcare.integrations.cursor import CursorAdapter
from clawcare.models import ExtensionRoot
from clawcare.scanner.scanner import scan_root

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


# ================================================================
# Unit tests: scan_scope returns correct globs per root kind
# ================================================================


class TestCursorScanScope:
    adapter = CursorAdapter()

    def test_project_root_only_scans_cursor_rules(self):
        root = ExtensionRoot(root_path="/fake", kind="cursor_project")
        scope = self.adapter.scan_scope(root)
        globs = scope["include_globs"]
        # Should include cursor-specific files
        assert any(".mdc" in g for g in globs)
        assert ".cursorrules" in globs
        # Should NOT include general code files
        assert "*.py" not in globs
        assert "*.js" not in globs
        assert "*.md" not in globs

    def test_skill_root_scans_all_code(self):
        root = ExtensionRoot(root_path="/fake", kind="cursor_skill")
        scope = self.adapter.scan_scope(root)
        globs = scope["include_globs"]
        assert "*.py" in globs
        assert "*.js" in globs
        assert "SKILL.md" in globs


class TestCodexScanScope:
    adapter = CodexAdapter()

    def test_project_root_only_scans_agents_md(self):
        root = ExtensionRoot(root_path="/fake", kind="codex_project")
        scope = self.adapter.scan_scope(root)
        globs = scope["include_globs"]
        assert "AGENTS.md" in globs
        assert "AGENTS.override.md" in globs
        # Should NOT include general code files
        assert "*.py" not in globs
        assert "*.js" not in globs

    def test_skill_root_scans_all_code(self):
        root = ExtensionRoot(root_path="/fake", kind="codex_skill")
        scope = self.adapter.scan_scope(root)
        globs = scope["include_globs"]
        assert "*.py" in globs
        assert "SKILL.md" in globs


class TestClaudeCodeScanScope:
    adapter = ClaudeCodeAdapter()

    def test_scope_always_includes_skill_files(self):
        root = ExtensionRoot(root_path="/fake", kind="claude_skill")
        scope = self.adapter.scan_scope(root)
        globs = scope["include_globs"]
        assert "*.md" in globs
        assert "*.py" in globs


# ================================================================
# Discovery tests: no whole-project fallback roots
# ================================================================


class TestNoFallbackRoots:
    """Verify adapters don't fall back to scanning the entire project."""

    def test_claude_no_unknown_root(self):
        adapter = ClaudeCodeAdapter()
        roots = adapter.discover_roots(os.path.join(FIXTURES, "claude_project"))
        kinds = {r.kind for r in roots}
        assert "claude_code_unknown" not in kinds

    def test_cursor_no_unknown_root(self):
        adapter = CursorAdapter()
        roots = adapter.discover_roots(os.path.join(FIXTURES, "cursor_project"))
        kinds = {r.kind for r in roots}
        assert "cursor_unknown" not in kinds

    def test_codex_no_unknown_root(self):
        adapter = CodexAdapter()
        roots = adapter.discover_roots(os.path.join(FIXTURES, "codex_project"))
        kinds = {r.kind for r in roots}
        assert "codex_unknown" not in kinds


class TestClaudeDiscoversDotClaudeSkills:
    """Claude Code adapter discovers skills under .claude/skills/."""

    adapter = ClaudeCodeAdapter()

    def test_finds_skill_in_claude_skills_dir(self):
        roots = self.adapter.discover_roots(os.path.join(FIXTURES, "claude_project"))
        skill_roots = [r for r in roots if r.kind == "claude_skill"]
        assert len(skill_roots) >= 1

    def test_skill_root_path_is_skill_dir(self):
        roots = self.adapter.discover_roots(os.path.join(FIXTURES, "claude_project"))
        skill_roots = [r for r in roots if r.kind == "claude_skill"]
        # The root should point to the skill directory, not the project
        for sr in skill_roots:
            assert "safe-helper" in sr.root_path


# ================================================================
# Integration tests: project-level files are NOT scanned
# ================================================================


class TestProjectFilesNotScanned:
    """End-to-end: decoy README.md files at the project root must NOT
    produce any findings. If they do, the scan scope is too broad."""

    def test_cursor_project_readme_not_scanned(self):
        adapter = CursorAdapter()
        target = os.path.join(FIXTURES, "cursor_project")
        roots = discover(adapter, target)
        all_findings = []
        for root in roots:
            scope = adapter.scan_scope(root)
            all_findings.extend(scan_root(root, scope))
        # The README.md has pipe-to-shell — if scanned, it would trigger
        readme_findings = [f for f in all_findings if "README.md" in f.file_path]
        assert readme_findings == [], f"README.md should not be scanned, but got: {readme_findings}"

    def test_codex_project_readme_not_scanned(self):
        adapter = CodexAdapter()
        target = os.path.join(FIXTURES, "codex_project")
        roots = discover(adapter, target)
        all_findings = []
        for root in roots:
            scope = adapter.scan_scope(root)
            all_findings.extend(scan_root(root, scope))
        readme_findings = [f for f in all_findings if "README.md" in f.file_path]
        assert readme_findings == [], f"README.md should not be scanned, but got: {readme_findings}"

    def test_claude_project_readme_not_scanned(self):
        adapter = ClaudeCodeAdapter()
        target = os.path.join(FIXTURES, "claude_project")
        roots = discover(adapter, target)
        all_findings = []
        for root in roots:
            scope = adapter.scan_scope(root)
            all_findings.extend(scan_root(root, scope))
        readme_findings = [f for f in all_findings if "README.md" in f.file_path]
        assert readme_findings == [], f"README.md should not be scanned, but got: {readme_findings}"

    def test_cursor_benign_project_still_clean(self):
        """Ensure the existing benign cursor project still has zero findings."""
        adapter = CursorAdapter()
        target = os.path.join(FIXTURES, "cursor_project")
        roots = discover(adapter, target)
        all_findings = []
        for root in roots:
            scope = adapter.scan_scope(root)
            all_findings.extend(scan_root(root, scope))
        assert len(all_findings) == 0
