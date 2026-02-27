"""Claude Code adapter (v1) — §10 of the design doc.

Detects the real Claude Code on-disk formats:
  - Skill: a directory containing ``SKILL.md`` with YAML frontmatter.
  - Plugin: a directory containing ``.claude-plugin/plugin.json``
    and optionally ``skills/``, ``hooks/``, etc.
"""

from __future__ import annotations

import json as _json
import os
from pathlib import Path

from clawcare.models import ExtensionRoot


class ClaudeCodeAdapter:
    """Adapter for Claude Code plugins and skills."""

    name: str = "claude_code"
    priority: int = 100

    # ── detect ──────────────────────────────────────────────────

    def detect(self, target_path: str) -> float:
        """Return confidence that *target_path* is a Claude Code skill or plugin."""
        p = Path(target_path)
        if not p.is_dir():
            return 0.0

        score = 0.0

        # Plugin marker: .claude-plugin/plugin.json
        if (p / ".claude-plugin" / "plugin.json").is_file():
            score += 0.5

        # Skill marker: SKILL.md at root
        if (p / "SKILL.md").is_file():
            score += 0.4

        # Skills within a plugin: skills/**/SKILL.md
        skills_dir = p / "skills"
        if skills_dir.is_dir():
            for child in skills_dir.iterdir():
                if child.is_dir() and (child / "SKILL.md").is_file():
                    score += 0.15

        # Hooks marker
        hooks_json = p / "hooks" / "hooks.json"
        if hooks_json.is_file():
            score += 0.1

        # Also check subdirectories for plugin bundles OR standalone skills
        for child in p.iterdir():
            if not child.is_dir():
                continue
            if (child / ".claude-plugin" / "plugin.json").is_file():
                score += 0.15
            elif (child / "SKILL.md").is_file():
                score += 0.15  # Boost score if children look like skills

        return min(score, 1.0)

    # ── discover_roots ──────────────────────────────────────────

    def discover_roots(self, target_path: str) -> list[ExtensionRoot]:
        p = Path(target_path)
        roots: list[ExtensionRoot] = []

        # Case 1: Target itself is a plugin (.claude-plugin/plugin.json exists)
        if (p / ".claude-plugin" / "plugin.json").is_file():
            roots.append(self._make_plugin_root(p))
            return roots

        # Case 2: Target itself is a standalone skill (SKILL.md at root)
        if (p / "SKILL.md").is_file():
            roots.append(self._make_skill_root(p))
            return roots

        # Case 3: Target contains .claude/skills/<name>/SKILL.md (real project layout)
        claude_skills = p / ".claude" / "skills"
        if claude_skills.is_dir():
            for child in sorted(claude_skills.iterdir()):
                if child.is_dir() and (child / "SKILL.md").is_file():
                    roots.append(self._make_skill_root(child))

        # Case 4: Target contains skills/<name>/SKILL.md (plugin layout)
        plain_skills = p / "skills"
        if plain_skills.is_dir():
            for child in sorted(plain_skills.iterdir()):
                if child.is_dir() and (child / "SKILL.md").is_file():
                    roots.append(self._make_skill_root(child))

        # Case 5: Target contains multiple plugins or skills as direct children
        if p.is_dir():
            for child in sorted(p.iterdir()):
                if not child.is_dir():
                    continue
                if child.name.startswith("."):
                    continue  # skip dotdirs (already handled .claude above)
                if child.name == "skills":
                    continue  # already handled above
                if (child / ".claude-plugin" / "plugin.json").is_file():
                    roots.append(self._make_plugin_root(child))
                elif (child / "SKILL.md").is_file():
                    roots.append(self._make_skill_root(child))

        return roots

    # ── scan_scope ──────────────────────────────────────────────

    def scan_scope(self, root: ExtensionRoot) -> dict:
        return {
            "include_globs": [
                "*.md", "*.py", "*.js", "*.ts", "*.sh", "*.bash",
                "*.json", "*.yml", "*.yaml", "*.txt", "*.ps1", "*.zsh",
            ],
            "exclude_globs": [
                "node_modules", "dist", "build", ".git", "__pycache__",
            ],
            "languages": ["python", "javascript", "typescript", "shell"],
        }

    # ── default_manifest ────────────────────────────────────────

    def default_manifest(self, root: ExtensionRoot) -> str | None:
        candidate = os.path.join(root.root_path, "clawcare.manifest.yml")
        if os.path.isfile(candidate):
            return candidate
        return None

    # ── helpers ──────────────────────────────────────────────────

    def _make_plugin_root(self, path: Path) -> ExtensionRoot:
        """Create an ExtensionRoot for a Claude Code plugin bundle."""
        metadata: dict = {}
        manifest = path / ".claude-plugin" / "plugin.json"
        if manifest.is_file():
            try:
                raw = _json.loads(manifest.read_text())
                metadata["name"] = raw.get("name", path.name)
                metadata["version"] = raw.get("version", "unknown")
                metadata["description"] = raw.get("description", "")
            except Exception:
                pass
        return ExtensionRoot(
            root_path=str(path.resolve()),
            kind="claude_plugin",
            metadata=metadata,
            manifest_path=str(manifest) if manifest.is_file() else None,
        )

    def _make_skill_root(self, path: Path) -> ExtensionRoot:
        """Create an ExtensionRoot for a standalone Claude Code skill."""
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
            kind="claude_skill",
            metadata=metadata,
        )
