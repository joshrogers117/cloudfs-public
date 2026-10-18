# Repo name guard

These hooks keep disallowed external-product names out of the committed repository.

## Files
- **`banned-terms.txt`** — the denylist. One POSIX extended-regex (ERE) per line,
  matched **case-insensitively**. This file is passed to `grep -E -f`, so to stay
  safe the scanners strip `#` comment lines and blank lines before using it — but
  prefer keeping this file as bare patterns only. To ban another name later, add a
  line (e.g. `acme[ ._-]?corp`).
- **`pre-commit`** — git hook; blocks a commit whose staged content matches the
  denylist. Install with `scripts/install-git-hooks.sh` (sets `core.hooksPath`).
- **`claude-name-guard.sh`** — Claude Code `PreToolUse` hook (wired in
  `.claude/settings.json`); blocks Write/Edit of a denylisted name into any file
  that would be committed (gitignored local-only files are allowed to contain them).
- CI: `.github/workflows/name-guard.yml` re-scans tracked files on push/PR.

## Local-only files allowed to contain the names (gitignored)
`research/`, `AUDIT-2026-06.md`, `HANDOFF-REMEDIATION.md`, `.claude/settings.local.json`.

## Bypass (discouraged)
`git commit --no-verify` skips the pre-commit hook. The CI guard still runs.
