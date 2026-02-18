"""Policy engine — load manifest and enforce capability restrictions (§7)."""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from clawcare.models import ExtensionRoot, Finding, PolicyManifest, Severity

# ---------------------------------------------------------------------------
# Load manifest
# ---------------------------------------------------------------------------

def load_manifest(path: str) -> PolicyManifest:
    """Parse a ``clawcare.manifest.yml`` file into a :class:`PolicyManifest`."""
    raw = yaml.safe_load(Path(path).read_text())
    if not isinstance(raw, dict):
        return PolicyManifest()

    perms = raw.get("permissions", {})
    return PolicyManifest(
        exec=perms.get("exec", "full"),
        network=perms.get("network", "unrestricted"),
        filesystem=perms.get("filesystem", "read_write"),
        secrets=perms.get("secrets", "unrestricted"),
        persistence=perms.get("persistence", "allowed"),
        allowed_domains=raw.get("allowed_domains", []),
        allowed_paths=raw.get("allowed_paths", ["**"]),
        fail_on=raw.get("fail_on"),
    )


# ---------------------------------------------------------------------------
# Manifest resolution (§7.1 precedence)
# ---------------------------------------------------------------------------

def resolve_manifest(
    root: ExtensionRoot,
    adapter,
    manifest_option: str = "auto",
) -> PolicyManifest | None:
    """Resolve and load the manifest for *root* according to precedence rules.

    *manifest_option* is the CLI ``--manifest`` value.
    """
    if manifest_option == "none":
        return None

    if manifest_option not in ("auto", "none"):
        # Explicit path — apply to all roots
        if os.path.isfile(manifest_option):
            return load_manifest(manifest_option)
        return None

    # auto resolution
    # 1. Adapter default
    adapter_manifest = adapter.default_manifest(root)
    if adapter_manifest and os.path.isfile(adapter_manifest):
        return load_manifest(adapter_manifest)

    # 2. root/clawcare.manifest.yml
    root_manifest = os.path.join(root.root_path, "clawcare.manifest.yml")
    if os.path.isfile(root_manifest):
        return load_manifest(root_manifest)

    return None


# ---------------------------------------------------------------------------
# Enforcement indicators (simple regex / substring checks)
# ---------------------------------------------------------------------------

_EXEC_INDICATORS = [
    "subprocess", "os.system", "os.popen", "child_process",
    "exec(", "execSync(", "spawn(",
    "Popen(", "shell=True",
]

_NETWORK_INDICATORS = [
    "http://", "https://", "requests.", "fetch(", "urllib",
    "axios", "httpx", "socket.connect",
]

_WRITE_INDICATORS = [
    'open(', "w)", '"w"', "'w'",
    "writeFile", "writeFileSync", "fs.write",
    "> ", ">> ", "tee ",
]

_PERSISTENCE_INDICATORS = [
    "crontab", "/etc/cron", "systemctl", "LaunchAgents",
    "LaunchDaemons", "launchctl",
]

_SECRET_INDICATORS = [
    "API_KEY", "SECRET_KEY", "ACCESS_TOKEN", "PRIVATE_KEY",
    "AWS_SECRET", "PASSWORD",
    "~/.ssh", "id_rsa", ".pem", "~/.aws/credentials",
    "~/.kube/config",
]


def _has_indicators(text: str, indicators: list[str]) -> bool:
    text_lower = text.lower()
    return any(ind.lower() in text_lower for ind in indicators)


# ---------------------------------------------------------------------------
# Enforcement (§7.3)
# ---------------------------------------------------------------------------

def enforce(
    manifest: PolicyManifest,
    root: ExtensionRoot,
    scanned_text: str,
) -> list[Finding]:
    """Check *scanned_text* (concatenated content of a root) against the manifest.

    Returns ``MANIFEST_*`` findings for violations.
    """
    violations: list[Finding] = []

    def _add(rule_id: str, explanation: str, severity: Severity = Severity.HIGH) -> None:
        violations.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                file_path=root.root_path,
                line=0,
                excerpt="(manifest enforcement)",
                explanation=explanation,
                remediation="Update the extension to comply with the manifest "
                            "or adjust the policy.",
            )
        )

    # exec: none
    if manifest.exec == "none" and _has_indicators(scanned_text, _EXEC_INDICATORS):
        _add("MANIFEST_EXEC", "Manifest forbids exec, but exec indicators found.")

    # network: none
    if manifest.network == "none" and _has_indicators(scanned_text, _NETWORK_INDICATORS):
        _add("MANIFEST_NETWORK", "Manifest forbids networking, but network indicators found.")

    # network: allowlist — extract domains and check
    if manifest.network == "allowlist" and manifest.allowed_domains:
        import re
        domains = set(re.findall(r"https?://([^/\s:\"']+)", scanned_text))
        disallowed = domains - set(manifest.allowed_domains)
        if disallowed:
            _add(
                "MANIFEST_NETWORK_DOMAIN",
                f"Domains not in allowlist: {', '.join(sorted(disallowed))}",
            )

    # filesystem: read_only
    if manifest.filesystem == "read_only" and _has_indicators(scanned_text, _WRITE_INDICATORS):
        _add("MANIFEST_FILESYSTEM", "Manifest requires read_only filesystem, but write indicators found.")

    # persistence: forbidden
    if manifest.persistence == "forbidden" and _has_indicators(scanned_text, _PERSISTENCE_INDICATORS):
        _add(
            "MANIFEST_PERSISTENCE",
            "Manifest forbids persistence, but persistence indicators found.",
            Severity.CRITICAL,
        )

    # secrets: none
    if manifest.secrets == "none" and _has_indicators(scanned_text, _SECRET_INDICATORS):
        _add("MANIFEST_SECRETS", "Manifest forbids secrets access, but secret indicators found.")

    return violations
