// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Stable, documented exit-code table for `cloudfs`.
 *
 * These codes are a public contract: scripts and CI pipelines branch on them,
 * so values must NOT change between releases (only new codes may be appended).
 * Mirrors the convention promised in SPEC §3.8 ("consistent 0/non-zero exit codes").
 *
 * Range conventions:
 *   0       success
 *   1       generic / unexpected error
 *   2       usage error (bad args/flags) — commander default
 *   10-19   auth & identity
 *   20-29   resource state (not found / conflict / locked)
 *   30-39   permission / access denied
 *   40-49   gateway / network / engine transport
 *   50-59   sync barriers (flush/wait) — timeouts & upload failures
 */
export const ExitCode = {
  OK: 0,
  GENERIC: 1,
  USAGE: 2,

  // 10-19 auth & identity
  NOT_AUTHENTICATED: 10,
  AUTH_FAILED: 11,
  TOKEN_EXPIRED: 12,

  // 20-29 resource state
  NOT_FOUND: 20,
  CONFLICT: 21,
  LOCKED: 22,
  NOT_CONNECTED: 23,

  // 30-39 permission
  PERMISSION_DENIED: 30,

  // 40-49 transport
  GATEWAY_ERROR: 40,
  NETWORK_ERROR: 41,
  ENGINE_UNAVAILABLE: 42,

  // 50-59 sync barriers
  SYNC_TIMEOUT: 50,
  SYNC_FAILED: 51,
} as const;

export type ExitCodeName = keyof typeof ExitCode;
export type ExitCodeValue = (typeof ExitCode)[ExitCodeName];

/** Human-readable description for each code (used by `cloudfs version --json` and docs). */
export const EXIT_CODE_DESCRIPTIONS: Record<number, string> = {
  0: "success",
  1: "generic/unexpected error",
  2: "usage error (bad arguments or flags)",
  10: "not authenticated (run `cloudfs auth login`)",
  11: "authentication failed (bad credentials/token)",
  12: "token expired or revoked",
  20: "resource not found",
  21: "conflict (resource already exists / state mismatch)",
  22: "resource is locked by another holder",
  23: "filespace not connected / not mounted",
  30: "permission denied (insufficient ACL/role)",
  40: "gateway returned an error",
  41: "network error reaching gateway",
  42: "local engine unavailable (control socket down)",
  50: "sync barrier timed out (flush/wait)",
  51: "sync failed (upload did not commit durably)",
};

/**
 * A CLI error that carries an exit code. Throw these from commands; `main`
 * catches them, renders the message, and exits with the carried code.
 */
export class CliError extends Error {
  readonly code: number;
  /** Optional structured detail surfaced in `--json` error output. */
  readonly detail?: Record<string, unknown>;

  constructor(message: string, code: number = ExitCode.GENERIC, detail?: Record<string, unknown>) {
    super(message);
    this.name = "CliError";
    this.code = code;
    this.detail = detail;
  }
}
