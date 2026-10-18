// SPDX-License-Identifier: AGPL-3.0-or-later
import { buildProgram } from "../src/app.js";
import type { GatewayClient } from "../src/gateway/client.js";
import { MockGatewayClient, type MockOptions } from "../src/gateway/mock.js";

export interface RunOutcome {
  code: number;
  stdout: string[];
  stderr: string[];
  /** Parsed JSON from the first stdout line, if it is JSON. */
  json: any;
}

/**
 * Run the CLI in-process with a captured output buffer and an injected mock,
 * returning the exit code and captured streams. No real process exit occurs.
 */
export async function runCli(args: string[], mockOpts: MockOptions = { authenticated: true }): Promise<RunOutcome> {
  return runCliWith(args, new MockGatewayClient(mockOpts));
}

/** Run the CLI with an explicitly injected GatewayClient (e.g. an HttpGatewayClient). */
export async function runCliWith(args: string[], client: GatewayClient): Promise<RunOutcome> {
  const capture = { stdout: [] as string[], stderr: [] as string[] };
  const { run } = buildProgram({ client, capture });
  const code = await run(args);
  const joined = capture.stdout.join("\n").trim();
  let json: any = undefined;
  try {
    json = JSON.parse(joined);
  } catch {
    /* not json */
  }
  return { code, stdout: capture.stdout, stderr: capture.stderr, json };
}
