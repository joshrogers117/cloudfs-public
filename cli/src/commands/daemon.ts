// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Command } from "commander";
import type { Context } from "../context.js";

/**
 * `cloudfs daemon` — headless mode for render nodes (SPEC §3.8).
 * Mounts a filespace on a server/render node with no GUI and stays resident,
 * serving the engine + mount. Authenticates non-interactively via CLOUDFS_TOKEN.
 *
 * In this stub the daemon performs the mount, prints its status, and (unless
 * `--once`) parks until a termination signal — the shape a systemd/launchd unit
 * or render-farm supervisor expects.
 */
export function registerDaemon(program: Command, ctx: () => Context): void {
  program
    .command("daemon [filespace]")
    .description("run headless: mount a filespace and stay resident (render nodes)")
    .option("--at <path>", "mount point")
    .option("--root-point <subpath>", "sub-path mount (RootPoint)")
    .option("--once", "mount, report status, and exit (do not park)")
    .action(async (filespace: string | undefined, opts: { at?: string; rootPoint?: string; once?: boolean }, cmd) => {
      const c = ctx();
      const fs = c.filespace(filespace);
      const mounted = await c.client.mount({ filespace: fs, at: opts.at, rootPoint: opts.rootPoint });

      const status = {
        mode: "daemon",
        filespace: mounted.id,
        mountPath: mounted.mountPath,
        rootPoint: mounted.rootPoint,
        pid: process.pid,
        headless: true,
      };

      if (opts.once) {
        cmd.result = { data: status, summary: `Daemon mounted ${mounted.id} at ${mounted.mountPath} (once).` };
        return;
      }

      // Park until a signal. Resolve on SIGINT/SIGTERM so the process exits 0.
      cmd.result = { data: status, summary: `Daemon running for ${mounted.id} at ${mounted.mountPath} (pid ${process.pid}). Ctrl-C to stop.` };
      await new Promise<void>((resolve) => {
        const stop = () => resolve();
        process.once("SIGINT", stop);
        process.once("SIGTERM", stop);
      });
    });
}
