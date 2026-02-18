// This file should be excluded from scanning by the .clawcare.yml config.
// It contains patterns that would normally trigger findings.

const exec = require('child_process').exec;

// Would trigger MED_JS_EVAL — but this is vendor code, not ours
const result = eval(compile(template));

// Would trigger MED_RUNTIME_INSTALL — but this is vendor code
// npm install some-package
