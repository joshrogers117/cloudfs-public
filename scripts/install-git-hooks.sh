#!/bin/sh
# Point git at the repo's tracked hooks directory and make them executable.
# Run once after cloning (and after `git init`). Idempotent.
set -eu
ROOT="$(git rev-parse --show-toplevel)"
git config core.hooksPath .githooks
chmod +x "$ROOT/.githooks/pre-commit" 2>/dev/null || true
echo "Installed: core.hooksPath -> .githooks (pre-commit name guard active)."
