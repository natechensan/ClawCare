"""Tests for the unified config loader (.clawcare.yml)."""

import os

from clawcare.config import (
    load_config,
    load_guard_config,
    load_project_config,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class TestDefaultConfig:
    def test_no_config_file_returns_defaults(self, tmp_path):
        cfg = load_project_config(str(tmp_path))
        assert cfg.fail_on == "high"
        assert cfg.block_local is False
        assert cfg.rulesets == []
        assert cfg.exclude == []
        assert cfg.ignore_rules == []
        assert cfg.max_file_size_kb == 512
        assert cfg.config_path is None


class TestLoadConfig:
    def test_loads_full_config(self, tmp_path):
        config = tmp_path / ".clawcare.yml"
        config.write_text("""\
scan:
  fail_on: critical
  block_local: true
  rulesets:
    - default
    - ./custom-rules
  exclude:
    - "vendor/**"
  ignore_rules:
    - MED_JS_EVAL
    - LOW_BROAD_GLOB
  max_file_size_kb: 1024
""")
        cfg = load_project_config(str(tmp_path))
        assert cfg.fail_on == "critical"
        assert cfg.block_local is True
        assert cfg.rulesets == ["default", "./custom-rules"]
        assert cfg.exclude == ["vendor/**"]
        assert cfg.ignore_rules == ["MED_JS_EVAL", "LOW_BROAD_GLOB"]
        assert cfg.max_file_size_kb == 1024
        assert cfg.config_path == str(config)

    def test_partial_config_uses_defaults(self, tmp_path):
        config = tmp_path / ".clawcare.yml"
        config.write_text("scan:\n  fail_on: medium\n")
        cfg = load_project_config(str(tmp_path))
        assert cfg.fail_on == "medium"
        assert cfg.block_local is False
        assert cfg.max_file_size_kb == 512

    def test_empty_file_returns_defaults(self, tmp_path):
        config = tmp_path / ".clawcare.yml"
        config.write_text("")
        cfg = load_project_config(str(tmp_path))
        assert cfg.fail_on == "high"

    def test_malformed_yaml_returns_defaults(self, tmp_path):
        config = tmp_path / ".clawcare.yml"
        config.write_text(": : invalid yaml [[[")
        cfg = load_project_config(str(tmp_path))
        assert cfg.fail_on == "high"

    def test_walks_up_to_find_config(self, tmp_path):
        """Config in parent dir is found when scanning a subdirectory."""
        config = tmp_path / ".clawcare.yml"
        config.write_text("scan:\n  fail_on: critical\n")
        subdir = tmp_path / "src" / "skills"
        subdir.mkdir(parents=True)
        cfg = load_project_config(str(subdir))
        assert cfg.fail_on == "critical"


# -----------------------------------------------------------------------
# Unified config loader
# -----------------------------------------------------------------------


class TestUnifiedConfig:
    """Tests for the merged project > user > defaults resolution."""

    def test_load_config_defaults_only(self, tmp_path):
        """No config files → all defaults."""
        cfg = load_config(scan_path=str(tmp_path))
        assert cfg.scan.fail_on == "high"
        assert cfg.guard.fail_on == "high"
        assert cfg.guard.audit.enabled is True
        assert cfg.project_config_path is None
        assert cfg.user_config_path is None

    def test_load_config_project_only(self, tmp_path):
        """Project .clawcare.yml with both scan and guard sections."""
        (tmp_path / ".clawcare.yml").write_text("""\
scan:
  fail_on: critical
guard:
  fail_on: medium
  audit:
    enabled: false
""")
        cfg = load_config(scan_path=str(tmp_path))
        assert cfg.scan.fail_on == "critical"
        assert cfg.guard.fail_on == "medium"
        assert cfg.guard.audit.enabled is False
        assert cfg.project_config_path is not None

    def test_project_overrides_user(self, tmp_path, monkeypatch):
        """Project-level values take priority over user-level values."""
        # Set up user config
        user_dir = tmp_path / "user_home" / ".clawcare"
        user_dir.mkdir(parents=True)
        user_cfg = user_dir / "config.yml"
        user_cfg.write_text("""\
scan:
  fail_on: low
guard:
  fail_on: low
  audit:
    enabled: false
""")

        # Set up project config
        project = tmp_path / "myproject"
        project.mkdir()
        (project / ".clawcare.yml").write_text("""\
scan:
  fail_on: critical
guard:
  fail_on: high
""")

        # Monkeypatch the user config path
        import clawcare.config as config_mod

        monkeypatch.setattr(config_mod, "USER_CONFIG_PATH", user_cfg)

        cfg = load_config(scan_path=str(project))
        # Project wins for scan
        assert cfg.scan.fail_on == "critical"
        # Project wins for guard
        assert cfg.guard.fail_on == "high"
        # User audit setting preserved where project doesn't override
        assert cfg.guard.audit.enabled is False

    def test_user_fallback_when_no_project(self, tmp_path, monkeypatch):
        """When no project config, user config is used as fallback."""
        user_dir = tmp_path / "user_home" / ".clawcare"
        user_dir.mkdir(parents=True)
        user_cfg = user_dir / "config.yml"
        user_cfg.write_text("""\
scan:
  fail_on: low
guard:
  fail_on: medium
""")

        project = tmp_path / "no_config_project"
        project.mkdir()

        import clawcare.config as config_mod

        monkeypatch.setattr(config_mod, "USER_CONFIG_PATH", user_cfg)

        cfg = load_config(scan_path=str(project))
        assert cfg.scan.fail_on == "low"
        assert cfg.guard.fail_on == "medium"
        assert cfg.project_config_path is None
        assert cfg.user_config_path == str(user_cfg)

    def test_explicit_config_path_skips_search(self, tmp_path):
        """When config_path is given, skip project/user search."""
        explicit = tmp_path / "custom.yml"
        explicit.write_text("""\
guard:
  fail_on: critical
""")
        cfg = load_config(config_path=str(explicit))
        assert cfg.guard.fail_on == "critical"
        assert cfg.scan.fail_on == "high"  # default

    def test_guard_config_from_project(self, tmp_path):
        """load_guard_config can read guard section from project .clawcare.yml."""
        (tmp_path / ".clawcare.yml").write_text("""\
guard:
  fail_on: critical
  audit:
    enabled: false
    log_path: /tmp/custom.jsonl
""")
        cfg = load_guard_config(scan_path=str(tmp_path))
        assert cfg.fail_on == "critical"
        assert cfg.audit.enabled is False
        assert cfg.audit.log_path == "/tmp/custom.jsonl"

    def test_combined_scan_guard_config(self, tmp_path):
        """Single .clawcare.yml with both sections works."""
        (tmp_path / ".clawcare.yml").write_text("""\
scan:
  fail_on: medium
  exclude:
    - "vendor/**"
  rulesets:
    - default
    - ./team-rules

guard:
  fail_on: critical
  audit:
    enabled: true
    log_path: "~/.clawcare/project-audit.jsonl"
""")
        cfg = load_config(scan_path=str(tmp_path))
        assert cfg.scan.fail_on == "medium"
        assert cfg.scan.exclude == ["vendor/**"]
        assert cfg.scan.rulesets == ["default", "./team-rules"]
        assert cfg.guard.fail_on == "critical"
        assert cfg.guard.audit.enabled is True


class TestIgnoreRulesIntegration:
    def test_ignore_rules_filters_findings(self, tmp_path):
        """End-to-end: .clawcare.yml with ignore_rules suppresses findings."""
        from clawcare.scanner.scanner import scan_file

        # Write config
        (tmp_path / ".clawcare.yml").write_text(
            "scan:\n  ignore_rules:\n    - MED_SUBPROCESS_SHELL\n"
        )

        # Write a file that triggers MED_SUBPROCESS_SHELL
        code = tmp_path / "test.py"
        code.write_text('import subprocess\nsubprocess.run("ls", shell=True)\n')

        # Scan without ignore
        findings = scan_file(code)
        rule_ids = {f.rule_id for f in findings}
        assert "MED_SUBPROCESS_SHELL" in rule_ids

        # Load config and filter
        cfg = load_project_config(str(tmp_path))
        ignored = set(cfg.ignore_rules)
        filtered = [f for f in findings if f.rule_id not in ignored]
        filtered_ids = {f.rule_id for f in filtered}
        assert "MED_SUBPROCESS_SHELL" not in filtered_ids
