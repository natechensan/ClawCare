"""Tests for report rendering (§13)."""

import json

import clawcare
from clawcare.models import AdapterInfo, Finding, ScanResult, Severity
from clawcare.report import render_json, render_text


def _make_result() -> ScanResult:
    r = ScanResult(
        scanned_path="/test/path",
        adapter=AdapterInfo(name="claude_code"),
        fail_on="high",
    )
    r.findings = [
        Finding("CRIT_PIPE_TO_SHELL", Severity.CRITICAL, "z.sh", 3, "curl | bash", "pipe to shell"),
        Finding("HIGH_REVERSE_SHELL", Severity.HIGH, "a.sh", 1, "/dev/tcp/...", "reverse shell"),
    ]
    r.manifest_violations = [
        Finding("MANIFEST_EXEC", Severity.HIGH, "/test/root", 0, "(manifest)", "exec violation"),
    ]
    return r


class TestTextOutput:
    def test_contains_adapter(self):
        output = render_text(_make_result(), color=False)
        assert "claude_code" in output
        assert clawcare.__version__ in output

    def test_contains_findings(self):
        output = render_text(_make_result(), color=False)
        assert "CRIT_PIPE_TO_SHELL" in output
        assert "HIGH_REVERSE_SHELL" in output

    def test_contains_summary(self):
        output = render_text(_make_result(), color=False)
        assert "Findings:" in output


class TestJsonOutput:
    def test_valid_json(self):
        raw = render_json(_make_result())
        doc = json.loads(raw)
        assert doc["tool"] == "clawcare"

    def test_adapter_attribution(self):
        doc = json.loads(render_json(_make_result()))
        assert doc["adapter_used"]["name"] == "claude_code"

    def test_deterministic_order(self):
        """Findings must be sorted: severity desc, file asc, line asc."""
        doc = json.loads(render_json(_make_result()))
        findings = doc["findings"]
        # CRITICAL first, then HIGH
        assert findings[0]["severity"] == "critical"
        assert findings[1]["severity"] == "high"

    def test_manifest_violations_separate(self):
        doc = json.loads(render_json(_make_result()))
        assert len(doc["manifest_violations"]) == 1
        assert doc["manifest_violations"][0]["rule_id"] == "MANIFEST_EXEC"

    def test_summary_counts(self):
        doc = json.loads(render_json(_make_result()))
        assert doc["summary"]["critical"] == 1
        assert doc["summary"]["high"] == 2  # 1 finding + 1 manifest
