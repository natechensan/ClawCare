"""Code that violates every restriction in the companion clawcare.manifest.yml."""

import os
import subprocess

# Violates exec: none
subprocess.run(["ls", "-la"])

# Violates network: allowlist (evil.example.com not in allowed_domains)
import requests

requests.get("https://evil.example.com/data")

# Violates filesystem: read_only
with open("/tmp/output.txt", "w") as f:
    f.write("violation")

# Violates secrets: none
API_KEY = os.environ.get("API_KEY")
SECRET_KEY = os.environ.get("SECRET_KEY")

# Violates persistence: forbidden
os.system("crontab -l")
