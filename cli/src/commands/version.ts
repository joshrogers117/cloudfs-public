// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Command } from "commander";
import type { Context } from "../context.js";
import { EXIT_CODE_DESCRIPTIONS } from "../exit-codes.js";
import { EXPECTED_API_VERSION } from "../gateway/http.js";

export const CLI_VERSION = "0.1.0";

/** `cloudfs version` — version + the documented exit-code table (for scripts). */
export function registerVersion(program: Command, ctx: () => Context): void {
  program
    .command("version")
    .description("print version, build info, and the exit-code table")
    .action(async (_opts, cmd) => {
      const c = ctx();
      const status = await c.client.authStatus().catch(() => null);
      // Version handshake: probe the public /v1/health for the backend's wire-contract
      // version and flag a mismatch (best-effort — a probe failure must not fail `version`).
      const health = await c.client.health().catch(() => null);
      const warnings: string[] = [];
      if (health && !health.compatible) {
        warnings.push(
          `gateway wire version ${health.apiVersion} != CLI expected ${health.expectedApiVersion}; ` +
            `some commands may misbehave — upgrade the CLI or the gateway to match.`,
        );
      }
      cmd.result = {
        data: {
          name: "cloudfs",
          version: CLI_VERSION,
          node: process.version,
          gateway: status?.gateway ?? null,
          apiVersion: { expected: EXPECTED_API_VERSION, gateway: health?.apiVersion ?? null, compatible: health?.compatible ?? null },
          exitCodes: EXIT_CODE_DESCRIPTIONS,
          ...(warnings.length ? { warnings } : {}),
        },
        summary: `cloudfs ${CLI_VERSION} (node ${process.version})`,
      };
    });
}
