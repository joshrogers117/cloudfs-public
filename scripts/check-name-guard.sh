#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Shared denylist scan for staged content and CI working-tree content.
set -eu

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
TERMS="$ROOT/.githooks/banned-terms.txt"
[ -f "$TERMS" ] || exit 0

PATS="$(mktemp)"
HITS="$(mktemp)"
trap 'rm -f "$PATS" "$HITS"' EXIT HUP INT TERM
grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$TERMS" > "$PATS" || true
[ -s "$PATS" ] || exit 0

PATHS='backend/src web/src web/public client-app/Sources client-app/Resources cloudfsd/Sources cli/src site'
set +e
if [ "${1:-}" = "--cached" ]; then
  git grep --cached -nIiE -f "$PATS" -- $PATHS > "$HITS" 2>/dev/null
else
  git grep -nIiE -f "$PATS" -- $PATHS > "$HITS" 2>/dev/null
fi
STATUS=$?
set -e

if [ "$STATUS" -eq 0 ]; then
  printf '\033[31m✖ branding guard failed\033[0m — disallowed names in shipped source/assets:\n' >&2
  cat "$HITS" >&2
  printf '\nSee CONTRIBUTING.md for the scanned paths and .githooks/banned-terms.txt for the denylist.\n' >&2
  exit 1
fi
if [ "$STATUS" -ne 1 ]; then
  printf 'Branding guard could not scan the selected paths (git grep status %s).\n' "$STATUS" >&2
  exit "$STATUS"
fi
printf 'clean — no denylisted names in shipped source/assets\n'
