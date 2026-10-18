#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Backend/web release gate. Native signing and mounted-volume tests run on macOS.
set -euo pipefail
cd "$(dirname "$0")/.."
sh scripts/check-name-guard.sh
node scripts/check-docs.mjs
node --test scripts/*.test.mjs
npm --prefix backend run typecheck
npm --prefix backend test
npm --prefix web test
npm --prefix web run lint
npm --prefix web run build
git diff --check
