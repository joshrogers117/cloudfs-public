// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Maps the gateway's standard error envelope + HTTP status (backend/API.md §2)
 * onto the CLI's STABLE exit-code table. We never change the exit codes — this
 * module is purely the translation from wire errors to `CliError(code)`.
 *
 * Wire envelope (API.md §2):
 *   { "error": "<code>", "reason"?: "<human detail>", "conflict"?: true, ... }
 */
import { CliError, ExitCode } from "../exit-codes.js";

export interface GatewayErrorBody {
  error?: string;
  reason?: string;
  conflict?: boolean;
  expected?: unknown;
  actual?: unknown;
  [k: string]: unknown;
}

/**
 * Translate an HTTP status + parsed error body into a CliError carrying one of
 * our documented exit codes. The mapping follows API.md §2's status table.
 */
export function mapGatewayError(status: number, body: GatewayErrorBody | undefined, url: string): CliError {
  const code = body?.error ?? "";
  const reason = body?.reason ? `: ${body.reason}` : "";
  const message = `${code || `http ${status}`}${reason}`;
  const detail: Record<string, unknown> = { status, gatewayError: code || null, url };
  if (body?.reason) detail.reason = body.reason;
  if (body?.conflict) {
    detail.conflict = true;
    if ("expected" in (body ?? {})) detail.expected = body!.expected;
    if ("actual" in (body ?? {})) detail.actual = body!.actual;
  }

  switch (status) {
    case 400:
      // malformed/missing body or query → usage error.
      return new CliError(message, ExitCode.USAGE, detail);
    case 401:
      // `expired` → token-expired (12); everything else → not authenticated (10).
      if (code === "expired") return new CliError(message, ExitCode.TOKEN_EXPIRED, detail);
      return new CliError(message, ExitCode.NOT_AUTHENTICATED, detail);
    case 403:
      // forbidden / forbidden_scope / cross_tenant / wrong_space → permission denied.
      return new CliError(message, ExitCode.PERMISSION_DENIED, detail);
    case 404:
      return new CliError(message, ExitCode.NOT_FOUND, detail);
    case 405:
      return new CliError(message, ExitCode.USAGE, detail);
    case 409:
      return new CliError(message, ExitCode.CONFLICT, detail);
    case 429: {
      // surface Retry-After if the caller recorded it on the body.
      return new CliError(message, ExitCode.GATEWAY_ERROR, detail);
    }
    default:
      // 5xx and anything else unexpected from the gateway.
      return new CliError(message, ExitCode.GATEWAY_ERROR, detail);
  }
}
