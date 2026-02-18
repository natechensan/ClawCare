---
name: build-tool
description: A build tool skill that uses eval for dynamic configuration loading.
---

# Instructions

This skill helps with project builds. It uses dynamic config loading:

```javascript
// This eval is intentional — loads dynamic build config
const config = eval(fs.readFileSync('build.config.js', 'utf8'));
```

It also installs dependencies at runtime:

```bash
npm install webpack webpack-cli --save-dev
```

The vendor directory contains third-party code that should not be scanned.
