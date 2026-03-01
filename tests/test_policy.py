"""Tests for policy manifest loading and enforcement."""

import pytest

from clawcare.models import ExtensionRoot, PolicyManifest, Severity
from clawcare.policy import enforce, load_manifest


@pytest.fixture
def manifest_file(tmp_path):
    """Write a clawcare.manifest.yml and return its path."""

    def _write(contents: str) -> str:
        p = tmp_path / "clawcare.manifest.yml"
        p.write_text(contents)
        return str(p)

    return _write


@pytest.fixture
def root():
    return ExtensionRoot(root_path="/test/root")


class TestLoadManifest:
    def test_full_manifest(self, manifest_file):
        m = load_manifest(
            manifest_file("""\
permissions:
  exec: none
  network: allowlist
  filesystem: read_only
  secrets: none
  persistence: forbidden
allowed_domains:
  - api.anthropic.com
fail_on: high
""")
        )
        assert m.exec == "none"
        assert m.network == "allowlist"
        assert m.filesystem == "read_only"
        assert m.secrets == "none"
        assert m.persistence == "forbidden"
        assert m.allowed_domains == ["api.anthropic.com"]
        assert m.fail_on == "high"

    def test_defaults(self, manifest_file):
        m = load_manifest(manifest_file("permissions: {}"))
        assert m.exec == "full"
        assert m.network == "unrestricted"


class TestEnforce:
    def test_exec_none_violates(self, root):
        m = PolicyManifest(exec="none")
        violations = enforce(m, root, "subprocess.run(...)")
        ids = {v.rule_id for v in violations}
        assert "MANIFEST_EXEC" in ids

    def test_exec_full_no_violation(self, root):
        m = PolicyManifest(exec="full")
        violations = enforce(m, root, "subprocess.run(...)")
        assert len(violations) == 0

    def test_network_none_violates(self, root):
        m = PolicyManifest(network="none")
        violations = enforce(m, root, "https://example.com")
        ids = {v.rule_id for v in violations}
        assert "MANIFEST_NETWORK" in ids

    def test_network_allowlist_violation(self, root):
        m = PolicyManifest(
            network="allowlist",
            allowed_domains=["api.anthropic.com"],
        )
        violations = enforce(m, root, "fetch('https://evil.example.com/data')")
        ids = {v.rule_id for v in violations}
        assert "MANIFEST_NETWORK_DOMAIN" in ids

    def test_network_allowlist_pass(self, root):
        m = PolicyManifest(
            network="allowlist",
            allowed_domains=["api.anthropic.com"],
        )
        violations = enforce(m, root, "fetch('https://api.anthropic.com/v1')")
        assert len(violations) == 0

    def test_filesystem_read_only_violates(self, root):
        m = PolicyManifest(filesystem="read_only")
        violations = enforce(m, root, 'open("/tmp/out", "w")')
        ids = {v.rule_id for v in violations}
        assert "MANIFEST_FILESYSTEM" in ids

    def test_persistence_forbidden_violates(self, root):
        m = PolicyManifest(persistence="forbidden")
        violations = enforce(m, root, "crontab -l")
        ids = {v.rule_id for v in violations}
        assert "MANIFEST_PERSISTENCE" in ids
        # persistence violation is CRITICAL
        assert any(v.severity == Severity.CRITICAL for v in violations)

    def test_secrets_none_violates(self, root):
        m = PolicyManifest(secrets="none")
        violations = enforce(m, root, 'os.environ["API_KEY"]')
        ids = {v.rule_id for v in violations}
        assert "MANIFEST_SECRETS" in ids
