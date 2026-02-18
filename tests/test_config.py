"""Tests for the project config loader (.clawcare.yml)."""

import os

from clawcare.config import load_project_config

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
