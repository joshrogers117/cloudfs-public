# Shipped branding guard

`banned-terms.txt` contains case-insensitive POSIX extended regular expressions for names excluded from shipped application source and assets. Comments and empty lines are ignored.

The shared implementation is `scripts/check-name-guard.sh`. It scans `backend/src`, `web/src`, `web/public`, `client-app/Sources`, `client-app/Resources`, `cloudfsd/Sources`, `cli/src` and `site`. Documentation and test fixtures are outside this branding check; they still need ordinary privacy and source review.

Run `scripts/install-git-hooks.sh` to install the staged-content pre-commit check. The `name-guard` GitHub workflow runs the same check on tracked source. `scripts/check-project.sh` includes it in the local release gate.
