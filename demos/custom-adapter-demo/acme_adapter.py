"""Example custom adapter — scans a hypothetical 'Acme Agent' platform.

This demonstrates how to write a ClawCare adapter for a new AI agent tool.
Acme Agent stores its skills in an `.acme/skills/` directory with a
`skill.toml` manifest in each skill folder.

Usage:
    clawcare scan ./demos/custom-adapter-demo --adapter import:demos.custom_adapter_demo.acme_adapter:AcmeAdapter
"""

from __future__ import annotations

import os
from pathlib import Path

from clawcare.models import ExtensionRoot


class AcmeAdapter:
    """Adapter for the hypothetical 'Acme Agent' platform."""

    name = "acme"
    version = "0.1.0"
    priority = 50

    _SKILL_MARKER = "skill.toml"

    def detect(self, target_path: str) -> float:
        """Return confidence that target_path is an Acme Agent project."""
        p = Path(target_path)
        if not p.is_dir():
            return 0.0

        score = 0.0

        # .acme/ directory is the primary signal
        if (p / ".acme").is_dir():
            score += 0.6

        # skill.toml at root means this IS a skill
        if (p / self._SKILL_MARKER).is_file():
            score += 0.4

        return min(score, 1.0)

    def discover_roots(self, target_path: str) -> list[ExtensionRoot]:
        """Discover Acme Agent skill roots."""
        p = Path(target_path)
        roots: list[ExtensionRoot] = []

        # Case 1: target is a single skill
        if (p / self._SKILL_MARKER).is_file():
            roots.append(self._make_root(p))
            return roots

        # Case 2: target has .acme/skills/ — discover each skill
        skills_dir = p / ".acme" / "skills"
        if skills_dir.is_dir():
            for child in sorted(skills_dir.iterdir()):
                if child.is_dir() and (child / self._SKILL_MARKER).is_file():
                    roots.append(self._make_root(child))

        return roots

    def scan_scope(self, root: ExtensionRoot) -> dict:
        """Only scan files within the skill directory."""
        return {
            "include_globs": [
                "*.toml", "*.md", "*.py", "*.js", "*.ts",
                "*.sh", "*.yml", "*.yaml", "*.json",
            ],
            "exclude_globs": [
                "node_modules", ".git", "__pycache__", ".venv",
            ],
        }

    def default_manifest(self, root: ExtensionRoot) -> str | None:
        candidate = os.path.join(root.root_path, "clawcare.manifest.yml")
        if os.path.isfile(candidate):
            return candidate
        return None

    @staticmethod
    def _make_root(path: Path) -> ExtensionRoot:
        return ExtensionRoot(
            root_path=str(path.resolve()),
            kind="acme_skill",
        )
