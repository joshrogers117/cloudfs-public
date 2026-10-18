// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Command } from "commander";
import type { Context } from "../context.js";
import { CliError, ExitCode } from "../exit-codes.js";
import { parseNumberFlag } from "../util.js";

/**
 * Sync barriers — the killer feature for pipelines (SPEC §3.8).
 *   `cloudfs flush <path>`  forces the write-back journal to drain.
 *   `cloudfs wait <path>`   blocks until all uploads for the path are durably
 *                           committed; returns non-zero on timeout/failure so a
 *                           render script knows output is safe before the next step.
 */
export function registerSync(program: Command, ctx: () => Context): void {
  program
    .command("flush <path> [filespace]")
    .description("force the write-back journal to drain for a path")
    .action(async (path: string, filespace: string | undefined, _opts, cmd) => {
      const c = ctx();
      const state = await c.client.flush(c.filespace(filespace), path);
      cmd.result = { data: state, summary: `Flushed ${path}; ${state.pendingUploads} uploads pending.` };
    });

  program
    .command("wait <path> [filespace]")
    .description("block until all uploads for a path are durably committed")
    .option("--timeout <seconds>", "max seconds to wait (0 = no timeout)", "300")
    .option("--interval <ms>", "poll interval in ms", "500")
    .action(async (path: string, filespace: string | undefined, opts: { timeout: string; interval: string }, cmd) => {
      const c = ctx();
      const fs = c.filespace(filespace);
      // FINDING 9: validate the numeric flags. A NaN `--timeout` previously meant the
      // deadline check never fired (infinite wait); a NaN/0 `--interval` busy-looped.
      // `--timeout` may be 0 (documented "no timeout"); `--interval` must be > 0.
      const timeoutMs = parseNumberFlag("--timeout", opts.timeout, { min: 0 }) * 1000;
      const intervalMs = parseNumberFlag("--interval", opts.interval, { positive: true });
      const start = Date.now();

      // Poll until in sync, the deadline passes, or an upload error surfaces.
      for (;;) {
        const state = await c.client.syncState(fs, path);
        if (state.inSync) {
          cmd.result = { data: state, summary: `In sync: ${path}.` };
          return;
        }
        if (timeoutMs > 0 && Date.now() - start >= timeoutMs) {
          throw new CliError(`timed out waiting for ${path} to sync (${state.pendingUploads} uploads pending)`, ExitCode.SYNC_TIMEOUT, {
            path,
            pendingUploads: state.pendingUploads,
            pendingBytes: state.pendingBytes,
          });
        }
        await new Promise((r) => setTimeout(r, intervalMs));
      }
    });
}
