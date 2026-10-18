#!/bin/sh
# Safe same-origin production deploy. --prepare creates new local config; --dry-run never deploys.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec node "$ROOT/scripts/deploy-prod.mjs" "$@"
