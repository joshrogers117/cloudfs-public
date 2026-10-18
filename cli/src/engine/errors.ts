// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Maps cloudfsd's JSON-RPC error objects onto the CLI's STABLE exit-code table
 * (CONTROL-API.md §2). The contract's `code` values were deliberately chosen to
 * map 1:1 onto `cli/src/exit-codes.ts`, so this is a tiny, explicit table — we
 * never change the exit codes, we only translate to them.
 *
 *   | JSON-RPC code | message class      | CLI exit code        |
 *   |---------------|--------------------|----------------------|
 *   | -32602        | invalid_params     | 2  USAGE             |
 *   | -32010        | not_connected      | 23 NOT_CONNECTED     |
 *   | -32020        | not_found          | 20 NOT_FOUND         |
 *   | -32021        | conflict           | 21 CONFLICT          |
 *   | -32022        | locked             | 22 LOCKED            |
 *   | -32030        | permission_denied  | 30 PERMISSION_DENIED |
 *   | -32040        | gateway_error      | 40 GATEWAY_ERROR     |
 *   | -32041        | network_error      | 41 NETWORK_ERROR     |
 *   | -32050        | sync_timeout       | 50 SYNC_TIMEOUT      |
 *   | -32051        | sync_failed        | 51 SYNC_FAILED       |
 *   | -32603        | internal           | 1  GENERIC           |
 */
import { CliError, ExitCode } from "../exit-codes.js";

export interface RpcErrorObject {
  code: number;
  message: string;
  data?: Record<string, unknown> | unknown;
}

/** JSON-RPC error code → stable CLI exit code. */
const CODE_MAP: Record<number, number> = {
  [-32602]: ExitCode.USAGE,
  [-32010]: ExitCode.NOT_CONNECTED,
  [-32020]: ExitCode.NOT_FOUND,
  [-32021]: ExitCode.CONFLICT,
  [-32022]: ExitCode.LOCKED,
  [-32030]: ExitCode.PERMISSION_DENIED,
  [-32040]: ExitCode.GATEWAY_ERROR,
  [-32041]: ExitCode.NETWORK_ERROR,
  [-32050]: ExitCode.SYNC_TIMEOUT,
  [-32051]: ExitCode.SYNC_FAILED,
  [-32603]: ExitCode.GENERIC,
};

/** Translate a JSON-RPC error object into a CliError carrying the mapped exit code. */
export function mapEngineError(err: RpcErrorObject): CliError {
  const exit = CODE_MAP[err.code] ?? ExitCode.GENERIC;
  const detail: Record<string, unknown> = { engineCode: err.code };
  if (err.data && typeof err.data === "object") Object.assign(detail, err.data as Record<string, unknown>);
  return new CliError(err.message || `engine error ${err.code}`, exit, detail);
}
