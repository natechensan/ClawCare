"""OpenAI Codex adapter — scans Codex CLI skills and AGENTS.md configs.

Codex on-disk format:
  - Skills: ``<skill-dir>/SKILL.md`` with YAML frontmatter (shared AgentSkills standard)
  - Project guidance: ``AGENTS.md`` (cascading hierarchy, root → subdirs)
  - Overrides: ``AGENTS.override.md`` (temporary higher-priority rules)
  - Skills typically live alongside or within a project that has ``AGENTS.md``.
"""

from __future__ import annotations

import os
from pathlib import Path

from clawcare.models import ExtensionRoot


class CodexAdapter:
    """Adapter for OpenAI Codex CLI skills and AGENTS.md projects."""

    name: str = "codex"
    priority: int = 80

    # Codex-specific markers
    _AGENTS_MD = "AGENTS.md"
    _AGENTS_OVERRIDE = "AGENTS.override.md"
    _SKILL_MD = "SKILL.md"

    # ── detect ──────────────────────────────────────────────────

    def detect(self, target_path: str) -> float:
        """Return confidence that *target_path* is a Codex project or skill."""
        p = Path(target_path)
        if not p.is_dir():
            return 0.0

        score = 0.0

        # AGENTS.md is the primary Codex signature
        if (p / self._AGENTS_MD).is_file():
            score += 0.5

        # Override file is a strong Codex-specific signal
        if (p / self._AGENTS_OVERRIDE).is_file():
            score += 0.2

        # Direct skill (SKILL.md at root)
        if (p / self._SKILL_MD).is_file():
            score += 0.3

        # Skills in subdirectories
        skills_found = 0
        for child in p.iterdir():
            if child.is_dir() and (child / self._SKILL_MD).is_file():
                skills_found += 1
        if skills_found > 0:
            score += min(0.15 * skills_found, 0.3)

        return min(score, 1.0)

    # ── discover_roots ──────────────────────────────────────────

    def discover_roots(self, target_path: str) -> list[ExtensionRoot]:
        p = Path(target_path)
        roots: list[ExtensionRoot] = []

        # Case 1: Target is a single skill directory
        if (p / self._SKILL_MD).is_file() and not (p / self._AGENTS_MD).is_file():
            roots.append(self._make_skill_root(p))
            return roots

        # Case 2: Target is a Codex project (has AGENTS.md)
        # Discover all skills within it + treat the project itself as a root
        if (p / self._AGENTS_MD).is_file():
            roots.append(self._make_project_root(p))

        # Find skills in subdirectories (bounded walk)
        for dirpath, _dirnames, filenames in os.walk(p):
            depth = str(dirpath).replace(str(p), "").count(os.sep)
            if depth > 4:
                continue
            if self._SKILL_MD in filenames:
                skill_path = Path(dirpath)
                # Don't double-count the project root
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

        if root.kind == "codex_project":
            # Project roots: only scan AGENTS.md and overrides
            base["include_globs"] = [
                "AGENTS.md", "AGENTS.override.md",
            ]
        else:
            # Skill roots: scan all relevant files within the skill
            base["include_globs"] = [
                "SKILL.md", "*.md", "*.py", "*.js", "*.ts",
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
        """Create an ExtensionRoot for a Codex project with AGENTS.md."""
        metadata: dict = {"has_agents_md": True}
        agents_md = path / self._AGENTS_MD
        if agents_md.is_file():
            try:
                # Extract first heading or first non-empty line as description
                for line in agents_md.read_text().splitlines():
                    stripped = line.strip()
                    if stripped and stripped.startswith("#"):
                        metadata["title"] = stripped.lstrip("# ").strip()
                        break
                    elif stripped:
                        metadata["title"] = stripped[:100]
                        break
            except Exception:
                pass

        override = path / self._AGENTS_OVERRIDE
        if override.is_file():
            metadata["has_override"] = True

        return ExtensionRoot(
            root_path=str(path.resolve()),
            kind="codex_project",
            metadata=metadata,
        )

    @staticmethod
    def _make_skill_root(path: Path) -> ExtensionRoot:
        """Create an ExtensionRoot for a Codex skill directory."""
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
            kind="codex_skill",
            metadata=metadata,
        )
