# Benign Documentation

This is a benign README file.

We can mention IPs like 127.0.0.1 in prose without triggering alerts.
We can also mention phone numbers like 555-0199 without triggering alerts.

However, if we put them in code blocks, they might trigger LOW severity alerts (but that's okay for now, the goal is to reduce noise in prose).

```bash
# This is a code block
echo "Hello World"
```
