"""Guard activate — install ClawCare hooks into platform config files.

Currently supports Claude Code and OpenClaw.

Claude Code settings
~~~~~~~~~~~~~~~~~~~~
File: ``~/.claude/settings.json`` (user-level)
  or: ``<project>/.claude/settings.json`` (project-level)

The hooks section is merged non-destructively — existing hooks are preserved,
and ClawCare entries are added only if not already present.

Result after activation::

    {
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "Bash",
            "hooks": [
              {"type": "command", "command": "clawcare guard hook --platform claude --stage pre"}
            ]
          }
        ],
        "PostToolUse": [
          {
            "matcher": "Bash",
            "hooks": [
              {"type": "command", "command": "clawcare guard hook --platform claude --stage post"}
            ]
          }
        ]
      }
    }

OpenClaw plugin
~~~~~~~~~~~~~~~
OpenClaw uses in-process TypeScript plugins with ``before_tool_call`` /
``after_tool_call`` hooks registered via ``api.registerHook(...)``.

Activation copies the ClawCare Guard TypeScript plugin into
``~/.openclaw/extensions/clawcare-guard/`` and enables it in
``~/.openclaw/openclaw.json`` under ``plugins.entries``.

See:
  https://docs.openclaw.ai/concepts/agent-loop#hook-points
  https://docs.openclaw.ai/tools/plugin#plugin-hooks
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Binary path resolution
# ---------------------------------------------------------------------------

def _resolve_binary_path() -> str:
    """Resolve the full absolute path to the ``clawcare`` CLI binary.

    Strategy (first match wins):

    1. ``shutil.which("clawcare")`` — works when the CLI is on PATH.
    2. ``<sys.executable parent>/clawcare`` — same venv/prefix as the
       running Python (covers ``pip install -e .``, conda, pyenv, etc.).
    3. Falls back to the bare string ``"clawcare"`` so activation still
       succeeds (with a warning logged by the caller).
    """
    found = shutil.which("clawcare")
    if found:
        return str(Path(found).resolve())

    # Same prefix as the running Python interpreter.
    candidate = Path(sys.executable).resolve().parent / "clawcare"
    if candidate.is_file():
        return str(candidate)

    return "clawcare"  # bare fallback


# ---------------------------------------------------------------------------
# Hook command templates  (bare versions — used for matching/compat)
# ---------------------------------------------------------------------------

_PRE_HOOK_SUFFIX = "guard hook --platform claude --stage pre"
_POST_HOOK_SUFFIX = "guard hook --platform claude --stage post"
_POST_FAILURE_HOOK_SUFFIX = "guard hook --platform claude --stage post-failure"

# Legacy bare-command constants (kept for _is_clawcare_hook matching).
_PRE_HOOK_CMD = "clawcare " + _PRE_HOOK_SUFFIX
_POST_HOOK_CMD = "clawcare " + _POST_HOOK_SUFFIX
_POST_FAILURE_HOOK_CMD = "clawcare " + _POST_FAILURE_HOOK_SUFFIX

# Matcher for tools that execute commands (string matching tool name).
_TOOL_MATCHER = "Bash"

# Default settings location.
CLAUDE_SETTINGS_DIR = Path.home() / ".claude"
CLAUDE_SETTINGS_PATH = CLAUDE_SETTINGS_DIR / "settings.json"

OPENCLAW_HOME = Path.home() / ".openclaw"
OPENCLAW_PLUGIN_ID = "clawcare-guard"

# Directory containing bundled plugin assets (TS source + package.json).
_PLUGIN_ASSETS_DIR = Path(__file__).parent / "plugin_assets"


def activate_claude(
    settings_path: str | Path | None = None,
    *,
    matcher: str | None = None,
    project_level: bool = False,
) -> Path:
    """Install ClawCare guard hooks into Claude Code ``settings.json``.

    Parameters
    ----------
    settings_path:
        Explicit path to settings.json.  Defaults to ``~/.claude/settings.json``.
    matcher:
        Tool name string to intercept (default ``"Bash"``).
    project_level:
        If True and *settings_path* is None, use ``.claude/settings.json``
        in the current directory instead of the user-level one.

    Returns
    -------
    The path where settings were written.
    """
    if settings_path:
        dest = Path(settings_path).expanduser()
    elif project_level:
        dest = Path.cwd() / ".claude" / "settings.json"
    else:
        dest = CLAUDE_SETTINGS_PATH

    # Load existing settings (or start fresh).
    settings = _load_json(dest)

    effective_matcher = matcher if matcher is not None else _TOOL_MATCHER

    # Resolve the full binary path so hooks survive across envs.
    binary = _resolve_binary_path()
    pre_cmd = f"{binary} {_PRE_HOOK_SUFFIX}"
    post_cmd = f"{binary} {_POST_HOOK_SUFFIX}"
    post_fail_cmd = f"{binary} {_POST_FAILURE_HOOK_SUFFIX}"

    # Ensure top-level hooks dict.
    hooks: dict[str, Any] = settings.setdefault("hooks", {})

    # Inject PreToolUse.
    _ensure_hook_entry(hooks, "PreToolUse", effective_matcher, pre_cmd)

    # Inject PostToolUse.
    _ensure_hook_entry(hooks, "PostToolUse", effective_matcher, post_cmd)

    # Inject PostToolUseFailure.
    _ensure_hook_entry(hooks, "PostToolUseFailure", effective_matcher, post_fail_cmd)

    # Write back.
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(settings, indent=2, ensure_ascii=False) + "\n")
    return dest


def deactivate_claude(settings_path: str | Path | None = None) -> bool:
    """Remove ClawCare guard hooks from Claude Code ``settings.json``.

    Returns True if any hooks were removed.
    """
    dest = Path(settings_path).expanduser() if settings_path else CLAUDE_SETTINGS_PATH

    if not dest.is_file():
        return False

    settings = _load_json(dest)
    hooks = settings.get("hooks", {})
    changed = False

    for event in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
        entries = hooks.get(event, [])
        new_entries: list[dict] = []
        for entry in entries:
            cmds = entry.get("hooks", [])
            filtered = [c for c in cmds if not _is_clawcare_hook(c)]
            if len(filtered) < len(cmds):
                changed = True
            if filtered:
                entry["hooks"] = filtered
                new_entries.append(entry)
            else:
                changed = True  # entire entry removed
        if new_entries:
            hooks[event] = new_entries
        elif event in hooks:
            del hooks[event]
            changed = True

    if changed:
        dest.write_text(json.dumps(settings, indent=2, ensure_ascii=False) + "\n")

    return changed


def is_claude_active(settings_path: str | Path | None = None) -> bool:
    """Check whether ClawCare hooks are installed in Claude Code settings."""
    dest = Path(settings_path).expanduser() if settings_path else CLAUDE_SETTINGS_PATH
    if not dest.is_file():
        return False
    settings = _load_json(dest)
    hooks = settings.get("hooks", {})
    for event in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
        for entry in hooks.get(event, []):
            for cmd in entry.get("hooks", []):
                if _is_clawcare_hook(cmd):
                    return True
    return False


def activate_openclaw(
    openclaw_home: str | Path | None = None,
) -> Path:
    """Install the ClawCare Guard TypeScript plugin for OpenClaw.

    Copies the bundled plugin assets (``index.ts``, ``package.json``) into
    ``<openclaw_home>/extensions/clawcare-guard/`` and enables the plugin in
    ``<openclaw_home>/openclaw.json``.

    Parameters
    ----------
    openclaw_home:
        Override the OpenClaw home directory (default ``~/.openclaw``).

    Returns
    -------
    The plugin directory where assets were installed.
    """
    home = Path(openclaw_home).expanduser() if openclaw_home else OPENCLAW_HOME
    plugin_dir = home / "extensions" / OPENCLAW_PLUGIN_ID
    plugin_dir.mkdir(parents=True, exist_ok=True)

    # Resolve the full binary path and bake it into the TS plugin source.
    binary = _resolve_binary_path()

    src_ts = _PLUGIN_ASSETS_DIR / "openclaw-plugin.ts"
    src_manifest = _PLUGIN_ASSETS_DIR / "openclaw.plugin.json"

    # Template the binary path into the TS source (replace placeholder).
    ts_source = src_ts.read_text()
    ts_source = ts_source.replace("__CLAWCARE_BIN__", binary)
    (plugin_dir / "index.ts").write_text(ts_source)

    shutil.copy2(src_manifest, plugin_dir / "openclaw.plugin.json")

    # Enable in openclaw.json.
    cfg_path = home / "openclaw.json"
    _openclaw_set_plugin_enabled(cfg_path, enabled=True, plugin_dir=plugin_dir)

    return plugin_dir


def deactivate_openclaw(
    openclaw_home: str | Path | None = None,
) -> bool:
    """Remove the ClawCare Guard plugin from OpenClaw.

    Removes the plugin directory and disables the entry in ``openclaw.json``.
    Returns True if anything was removed.
    """
    home = Path(openclaw_home).expanduser() if openclaw_home else OPENCLAW_HOME
    plugin_dir = home / "extensions" / OPENCLAW_PLUGIN_ID
    cfg_path = home / "openclaw.json"

    changed = False

    if plugin_dir.is_dir():
        shutil.rmtree(plugin_dir)
        changed = True

    if cfg_path.is_file():
        changed = _openclaw_set_plugin_enabled(
            cfg_path, enabled=False, plugin_dir=plugin_dir,
        ) or changed

    return changed


def is_openclaw_active(
    openclaw_home: str | Path | None = None,
) -> bool:
    """Return True if the ClawCare Guard plugin is installed for OpenClaw."""
    home = Path(openclaw_home).expanduser() if openclaw_home else OPENCLAW_HOME
    plugin_dir = home / "extensions" / OPENCLAW_PLUGIN_ID

    # Plugin files must exist.
    if not (plugin_dir / "index.ts").is_file():
        return False

    # Check config.
    cfg_path = home / "openclaw.json"
    if not cfg_path.is_file():
        return False

    config = _load_json(cfg_path)
    entries = config.get("plugins", {}).get("entries", {})
    entry = entries.get(OPENCLAW_PLUGIN_ID, {})
    return entry.get("enabled", False) is True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_json(path: Path) -> dict:
    """Load a JSON file, returning ``{}`` if missing or invalid."""
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text())
        return raw if isinstance(raw, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _write_json(path: Path, data: dict) -> None:
    """Write a JSON file with pretty formatting."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def _openclaw_set_plugin_enabled(
    cfg_path: Path,
    *,
    enabled: bool,
    plugin_dir: Path | None = None,
) -> bool:
    """Toggle the clawcare-guard entry in ``openclaw.json``.

    Creates the file and ``plugins.entries`` structure if needed.
    Also manages ``plugins.allow`` (trust) and ``plugins.load.paths``
    (load-path provenance) to suppress OpenClaw startup warnings.
    Returns True if the config was modified.
    """
    config = _load_json(cfg_path)
    plugins = config.setdefault("plugins", {})
    entries = plugins.setdefault("entries", {})
    allow: list[str] = plugins.setdefault("allow", [])
    load: dict = plugins.setdefault("load", {})
    paths: list[str] = load.setdefault("paths", [])
    entry = entries.get(OPENCLAW_PLUGIN_ID, {})

    plugin_path_str = str(plugin_dir) if plugin_dir else None

    old_enabled = entry.get("enabled", None)
    changed = False

    if enabled:
        # Replace with a clean entry — only OpenClaw-valid keys.
        entries[OPENCLAW_PLUGIN_ID] = {"enabled": True}
        # Pin trust so OpenClaw doesn't warn about non-bundled plugins.
        if OPENCLAW_PLUGIN_ID not in allow:
            allow.append(OPENCLAW_PLUGIN_ID)
            changed = True
        # Add to load.paths for load-path provenance.
        if plugin_path_str and plugin_path_str not in paths:
            paths.append(plugin_path_str)
            changed = True
    else:
        if OPENCLAW_PLUGIN_ID in entries:
            entry["enabled"] = False
            entries[OPENCLAW_PLUGIN_ID] = entry
        else:
            return False
        # Remove from allow list when deactivating.
        if OPENCLAW_PLUGIN_ID in allow:
            allow.remove(OPENCLAW_PLUGIN_ID)
            changed = True
        # Remove from load.paths when deactivating.
        if plugin_path_str and plugin_path_str in paths:
            paths.remove(plugin_path_str)
            changed = True

    if old_enabled == enabled and not changed:
        return False

    _write_json(cfg_path, config)
    return True


_ALL_HOOK_CMDS = {_PRE_HOOK_CMD, _POST_HOOK_CMD, _POST_FAILURE_HOOK_CMD}
_HOOK_SUFFIXES = {_PRE_HOOK_SUFFIX, _POST_HOOK_SUFFIX, _POST_FAILURE_HOOK_SUFFIX}


def _is_clawcare_hook(hook: Any) -> bool:
    """Return True if *hook* is a ClawCare guard command.

    Matches both bare ``clawcare guard hook …`` and full-path variants
    like ``/usr/local/bin/clawcare guard hook …``.
    """
    cmd = ""
    if isinstance(hook, str):
        cmd = hook
    elif isinstance(hook, dict):
        cmd = hook.get("command", "")
    else:
        return False

    # Exact match against bare commands.
    if cmd in _ALL_HOOK_CMDS:
        return True

    # Suffix match — handles baked absolute paths.
    # e.g. "/opt/homebrew/bin/clawcare guard hook --platform claude --stage pre"
    return any(cmd.endswith(" " + s) for s in _HOOK_SUFFIXES)


def _ensure_hook_entry(
    hooks: dict[str, Any],
    event: str,
    matcher: str,
    command: str,
) -> None:
    """Add *command* under *event* → *matcher* if not already present."""
    entries: list[dict] = hooks.setdefault(event, [])
    hook_obj = {"type": "command", "command": command}

    for entry in entries:
        if entry.get("matcher") == matcher:
            cmds: list = entry.setdefault("hooks", [])
            if not any(_is_clawcare_hook(c) and
                       (c if isinstance(c, str) else c.get("command")) == command
                       for c in cmds):
                cmds.append(hook_obj)
            return

    entries.append({"matcher": matcher, "hooks": [hook_obj]})
