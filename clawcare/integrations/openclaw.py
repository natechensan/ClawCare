"""OpenClaw adapter (v2) — §11 of the design doc."""

from __future__ import annotations

import os
from pathlib import Path

from clawcare.models import ExtensionRoot


class OpenClawAdapter:
    """Adapter for OpenClaw skills defined around SKILL.md."""

    name: str = "openclaw"
    version: str = "0.1.0"
    priority: int = 90

    # ── detect ──────────────────────────────────────────────────

    def detect(self, target_path: str) -> float:
        """Return confidence that *target_path* contains OpenClaw skills."""
        p = Path(target_path)
        if not p.is_dir():
            return 0.0

        score = 0.0

        # Strong OpenClaw-specific signal: .opencode/skills/*/SKILL.md
        opencode_skills = p / ".opencode" / "skills"
        if opencode_skills.is_dir():
            for child in opencode_skills.iterdir():
                if child.is_dir() and (child / "SKILL.md").is_file():
                    return 0.95  # near-certain OpenClaw

        # Compatible paths: .claude/skills/ or .agents/skills/
        for compat_dir in (".claude/skills", ".agents/skills"):
            compat = p / compat_dir
            if compat.is_dir():
                for child in compat.iterdir():
                    if child.is_dir() and (child / "SKILL.md").is_file():
                        score = max(score, 0.5)

        # Direct SKILL.md at root (standalone skill)
        if (p / "SKILL.md").is_file():
            score = max(score, 0.4)

        # Search for any **/SKILL.md (bounded depth)
        if score == 0.0:
            found = 0
            for root, _dirs, files in os.walk(p):
                depth = str(root).replace(str(p), "").count(os.sep)
                if depth > 4:
                    continue
                if "SKILL.md" in files:
                    found += 1
                    if found >= 2:
                        return 0.3
            if found == 1:
                score = 0.2

        return score

    # ── discover_roots ──────────────────────────────────────────

    def discover_roots(self, target_path: str) -> list[ExtensionRoot]:
        p = Path(target_path)

        # If target itself has SKILL.md → single root
        if (p / "SKILL.md").is_file():
            return [self._make_root(p)]

        # Find all **/SKILL.md
        roots: list[ExtensionRoot] = []
        for root, _dirs, files in os.walk(p):
            if "SKILL.md" in files:
                roots.append(self._make_root(Path(root)))

        roots.sort(key=lambda r: r.root_path)
        return roots

    # ── scan_scope ──────────────────────────────────────────────

    def scan_scope(self, root: ExtensionRoot) -> dict:
        return {
            "include_globs": [
                "SKILL.md", "*.md", "*.py", "*.js", "*.ts",
                "*.sh", "*.bash", "*.zsh", "*.ps1",
                "*.yml", "*.yaml", "*.json", "*.txt",
            ],
            "exclude_globs": [
                "node_modules", "dist", "build", ".git",
                "__pycache__", ".venv", "venv",
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

    @staticmethod
    def _make_root(path: Path) -> ExtensionRoot:
        metadata: dict = {}
        skill_md = path / "SKILL.md"
        if skill_md.is_file():
            try:
                text = skill_md.read_text()
                # Try to extract name/description from YAML frontmatter
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
            kind="openclaw_skill",
            metadata=metadata,
        )
