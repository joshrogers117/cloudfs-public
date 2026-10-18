// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Command } from "commander";
import type { Context } from "../context.js";

/** `cloudfs mount` / `cloudfs unmount` — engine mounts incl. sub-path RootPoint. */
export function registerMount(program: Command, ctx: () => Context): void {
  program
    .command("mount [filespace]")
    .description("mount a filespace as a local volume")
    .option("--at <path>", "mount point (default: /Volumes/<filespace>)")
    .option("--root-point <subpath>", "sub-path mount (RootPoint, SPEC §4.3)")
    .action(async (filespace: string | undefined, opts: { at?: string; rootPoint?: string }, cmd) => {
      const c = ctx();
      const f = await c.client.mount({ filespace: c.filespace(filespace), at: opts.at, rootPoint: opts.rootPoint });
      cmd.result = { data: f, summary: `Mounted ${f.id} at ${f.mountPath}.` };
    });

  program
    .command("unmount [filespace]")
    .alias("umount")
    .description("unmount a filespace")
    .action(async (filespace: string | undefined, _opts, cmd) => {
      const c = ctx();
      const f = await c.client.unmount(c.filespace(filespace));
      cmd.result = { data: f, summary: `Unmounted ${f.id}.` };
    });
}
