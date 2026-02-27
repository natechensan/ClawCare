"""Cursor adapter — scans Cursor agent skills and .cursor/rules/ configs.

Cursor on-disk format:
  - Rules: ``.cursor/rules/*.mdc`` (Markdown with optional YAML frontmatter)
  - Legacy: ``.cursorrules`` file at project root
  - Skills: ``SKILL.md`` in skill directories (shared AgentSkills standard)
  - Also compatible with ``AGENTS.md`` at project root

``.mdc`` files can include frontmatter with ``description`` and ``globs``
fields that control when rules are applied.
"""

from __future__ import annotations

import os
from pathlib import Path

from clawcare.models import ExtensionRoot


class CursorAdapter:
    """Adapter for Cursor AI agent skills and .cursor/rules/ projects."""

    name: str = "cursor"
    priority: int = 70

    # ── detect ──────────────────────────────────────────────────

    def detect(self, target_path: str) -> float:
        """Return confidence that *target_path* is a Cursor project or skill."""
        p = Path(target_path)
        if not p.is_dir():
            return 0.0

        score = 0.0

        # .cursor/rules/ is the primary Cursor signature
        cursor_rules = p / ".cursor" / "rules"
        if cursor_rules.is_dir():
            mdc_files = list(cursor_rules.glob("*.mdc"))
            md_files = list(cursor_rules.glob("*.md"))
            rule_count = len(mdc_files) + len(md_files)
            if rule_count > 0:
                score += 0.6
            else:
                score += 0.3  # Empty .cursor/rules/ dir still signals Cursor

        # Legacy .cursorrules at root
        if (p / ".cursorrules").is_file():
            score += 0.3

        # .cursor/ directory exists (even without rules/)
        if (p / ".cursor").is_dir() and score == 0:
            score += 0.2

        # Skills (SKILL.md) — shared format, lower weight
        if (p / "SKILL.md").is_file():
            score += 0.15

        # Skills in subdirectories
        for child in p.iterdir():
            if child.is_dir() and (child / "SKILL.md").is_file():
                score += 0.1
                break  # one is enough for the signal

        return min(score, 1.0)

    # ── discover_roots ──────────────────────────────────────────

    def discover_roots(self, target_path: str) -> list[ExtensionRoot]:
        p = Path(target_path)
        roots: list[ExtensionRoot] = []

        # Case 1: Target is a Cursor project (.cursor/ exists)
        has_cursor_dir = (p / ".cursor").is_dir()
        has_cursorrules = (p / ".cursorrules").is_file()

        if has_cursor_dir or has_cursorrules:
            roots.append(self._make_project_root(p))

        # Case 2: Target is a single skill directory
        if (p / "SKILL.md").is_file() and not has_cursor_dir:
            roots.append(self._make_skill_root(p))
            return roots

        # Find skills in subdirectories (bounded walk)
        for dirpath, _dirnames, filenames in os.walk(p):
            depth = str(dirpath).replace(str(p), "").count(os.sep)
            if depth > 4:
                continue
            if "SKILL.md" in filenames:
                skill_path = Path(dirpath)
                if skill_path != p:
                    roots.append(self._make_skill_root(skill_path))

        roots.sort(key=lambda r: r.root_path)
        return roots

    # ── scan_scope ──────────────────────────────────────────────

    def scan_scope(self, root: ExtensionRoot) -> dict:
        base = {
            "exclude_globs": [
                "node_modules", "dist", "build", ".git",
                "__pycache__", ".venv", "venv",
            ],
            "languages": ["python", "javascript", "typescript", "shell"],
        }

        if root.kind == "cursor_project":
            # Project roots: only scan .cursor/ rules and .cursorrules
            base["include_globs"] = [
                ".cursor/rules/*.mdc", ".cursor/rules/*.md",
                ".cursorrules",
            ]
        else:
            # Skill roots: scan all relevant files within the skill
            base["include_globs"] = [
                "SKILL.md", "*.mdc", "*.md", "*.py", "*.js", "*.ts",
                "*.sh", "*.bash", "*.json", "*.yml", "*.yaml",
                "*.txt", "*.ps1", "*.zsh",
            ]

        return base

    # ── default_manifest ────────────────────────────────────────

    def default_manifest(self, root: ExtensionRoot) -> str | None:
        candidate = os.path.join(root.root_path, "clawcare.manifest.yml")
        if os.path.isfile(candidate):
            return candidate
        return None

    # ── helpers ──────────────────────────────────────────────────

    def _make_project_root(self, path: Path) -> ExtensionRoot:
        """Create an ExtensionRoot for a Cursor project."""
        metadata: dict = {}

        # Count .mdc rules
        cursor_rules = path / ".cursor" / "rules"
        if cursor_rules.is_dir():
            mdc_files = list(cursor_rules.glob("*.mdc")) + list(cursor_rules.glob("*.md"))
            metadata["rule_count"] = len(mdc_files)
            metadata["rule_files"] = [f.name for f in sorted(mdc_files)]

        if (path / ".cursorrules").is_file():
            metadata["has_legacy_cursorrules"] = True

        return ExtensionRoot(
            root_path=str(path.resolve()),
            kind="cursor_project",
            metadata=metadata,
        )

    @staticmethod
    def _make_skill_root(path: Path) -> ExtensionRoot:
        """Create an ExtensionRoot for a Cursor skill directory."""
        metadata: dict = {}
        skill_md = path / "SKILL.md"
        if skill_md.is_file():
            try:
                text = skill_md.read_text()
                if text.startswith("---"):
                    import yaml
                    end = text.index("---", 3)
                    fm = yaml.safe_load(text[3:end])
                    if isinstance(fm, dict):
                        metadata["name"] = fm.get("name", path.name)
                        metadata["description"] = fm.get("description", "")
            except Exception:
                pass
        return ExtensionRoot(
            root_path=str(path.resolve()),
            kind="cursor_skill",
            metadata=metadata,
        )
