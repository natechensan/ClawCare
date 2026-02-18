"""Golden tests — end-to-end against platform-specific fixture directories.

Fixtures:
  Claude Code:
    - claude_benign_skill/           → standalone skill (SKILL.md)
    - claude_malicious_plugin/       → plugin (.claude-plugin/ + skills/)
    - claude_manifest_violation/     → plugin with clawcare.manifest.yml violations
  OpenClaw:
    - openclaw_benign_project/       → project with .opencode/skills/
    - openclaw_malicious_project/    → project with malicious .opencode/skills/
"""

import contextlib
import os

from clawcare.discovery import discover
from clawcare.gate import decide
from clawcare.integrations.claude_code import ClaudeCodeAdapter
from clawcare.integrations.openclaw import OpenClawAdapter
from clawcare.models import AdapterInfo, ScanResult, Severity
from clawcare.policy import enforce, resolve_manifest
from clawcare.scanner.scanner import collect_files, scan_root

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _run_engine(fixture_name, adapter, ci=False, manifest_opt="auto"):
    """Run the full engine pipeline against a fixture."""
    target = os.path.join(FIXTURES, fixture_name)
    roots = discover(adapter, target)

    result = ScanResult(
        scanned_path=target,
        adapter=AdapterInfo(name=adapter.name, version=adapter.version),
        roots=roots,
        fail_on="high",
    )

    for root in roots:
        scope = adapter.scan_scope(root)
        findings = scan_root(root, scope)
        result.findings.extend(findings)

        manifest = resolve_manifest(root, adapter, manifest_opt)
        if manifest is not None:
            texts = []
            for fpath in collect_files(root, scope.get("include_globs"),
                                       scope.get("exclude_globs")):
                with contextlib.suppress(OSError):
                    texts.append(fpath.read_text(errors="replace"))
            violations = enforce(manifest, root, "\n".join(texts))
            result.manifest_violations.extend(violations)

    result.compute_risk_score()
    exit_code = decide(result, ci_flag=ci, fail_on="high")
    return result, exit_code


# ================================================================
# Claude Code fixtures
# ================================================================

claude = ClaudeCodeAdapter()


class TestClaudeBenignSkill:
    def test_no_findings(self):
        result, _ = _run_engine("claude_benign_skill", claude)
        assert len(result.findings) == 0

    def test_exits_zero_in_ci(self):
        _, code = _run_engine("claude_benign_skill", claude, ci=True)
        assert code == 0

    def test_detected_as_skill(self):
        result, _ = _run_engine("claude_benign_skill", claude)
        assert any(r.kind == "claude_skill" for r in result.roots)


class TestClaudeMaliciousPlugin:
    def test_has_critical_findings(self):
        result, _ = _run_engine("claude_malicious_plugin", claude)
        assert Severity.CRITICAL in {f.severity for f in result.findings}

    def test_has_high_findings(self):
        result, _ = _run_engine("claude_malicious_plugin", claude)
        assert Severity.HIGH in {f.severity for f in result.findings}

    def test_blocks_in_ci(self):
        _, code = _run_engine("claude_malicious_plugin", claude, ci=True)
        assert code == 2

    def test_warns_locally(self):
        _, code = _run_engine("claude_malicious_plugin", claude)
        assert code == 0

    def test_risk_score_high(self):
        result, _ = _run_engine("claude_malicious_plugin", claude)
        assert result.risk_score >= 50

    def test_detected_as_plugin(self):
        result, _ = _run_engine("claude_malicious_plugin", claude)
        assert any(r.kind == "claude_plugin" for r in result.roots)


class TestClaudeManifestViolation:
    def test_has_manifest_violations(self):
        result, _ = _run_engine("claude_manifest_violation", claude)
        assert len(result.manifest_violations) > 0
        assert any(v.rule_id.startswith("MANIFEST_")
                    for v in result.manifest_violations)

    def test_violations_are_high_or_critical(self):
        result, _ = _run_engine("claude_manifest_violation", claude)
        for v in result.manifest_violations:
            assert v.severity >= Severity.HIGH

    def test_blocks_in_ci(self):
        _, code = _run_engine("claude_manifest_violation", claude, ci=True)
        assert code == 2


# ================================================================
# OpenClaw fixtures
# ================================================================

openclaw = OpenClawAdapter()


class TestOpenClawBenignProject:
    def test_no_findings(self):
        result, _ = _run_engine("openclaw_benign_project", openclaw)
        assert len(result.findings) == 0

    def test_exits_zero_in_ci(self):
        _, code = _run_engine("openclaw_benign_project", openclaw, ci=True)
        assert code == 0

    def test_detected_as_openclaw(self):
        result, _ = _run_engine("openclaw_benign_project", openclaw)
        assert any(r.kind == "openclaw_skill" for r in result.roots)


class TestOpenClawMaliciousProject:
    def test_has_critical_findings(self):
        result, _ = _run_engine("openclaw_malicious_project", openclaw)
        assert Severity.CRITICAL in {f.severity for f in result.findings}

    def test_has_high_findings(self):
        result, _ = _run_engine("openclaw_malicious_project", openclaw)
        assert Severity.HIGH in {f.severity for f in result.findings}

    def test_blocks_in_ci(self):
        _, code = _run_engine("openclaw_malicious_project", openclaw, ci=True)
        assert code == 2

    def test_warns_locally(self):
        _, code = _run_engine("openclaw_malicious_project", openclaw)
        assert code == 0

    def test_risk_score_high(self):
        result, _ = _run_engine("openclaw_malicious_project", openclaw)
        assert result.risk_score >= 50
