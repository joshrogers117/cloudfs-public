// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Command } from "commander";
import type { Context } from "../context.js";

/** `cloudfs snapshot list|create|restore` (SPEC §4.7, R8). */
export function registerSnapshot(program: Command, ctx: () => Context): void {
  const snap = program.command("snapshot").alias("snap").description("point-in-time snapshots");

  snap
    .command("list [filespace]")
    .description("list snapshots")
    .action(async (filespace: string | undefined, _opts, cmd) => {
      const c = ctx();
      const list = await c.client.snapshotList(c.filespace(filespace));
      cmd.result = { data: list, table: list.map((s) => ({ id: s.id, label: s.label ?? "", scope: s.scope, created: s.createdAt, immutableUntil: s.immutableUntil ?? "-" })) };
    });

  snap
    .command("create [filespace]")
    .description("create an on-demand snapshot")
    .option("--scope <path>", "subtree to snapshot (default: /)")
    .option("--label <label>", "human label")
    .action(async (filespace: string | undefined, opts: { scope?: string; label?: string }, cmd) => {
      const c = ctx();
      const s = await c.client.snapshotCreate({ filespace: c.filespace(filespace), scope: opts.scope, label: opts.label });
      cmd.result = { data: s, summary: `Created snapshot ${s.id}.` };
    });

  snap
    .command("restore <snapshotId> <path> [filespace]")
    .description("restore a file (or, with --recursive, a subtree) from a snapshot")
    .option("-r, --recursive", "restore the whole subtree under <path>")
    .option("--mode <mode>", "restore mode (passed through to the gateway)")
    .action(async (snapshotId: string, path: string, filespace: string | undefined, opts: { recursive?: boolean; mode?: string }, cmd) => {
      const c = ctx();
      const res = await c.client.snapshotRestore({
        filespace: c.filespace(filespace),
        id: snapshotId,
        path,
        recursive: opts.recursive,
        mode: opts.mode,
      });
      // Table view = the counts; full arrays stay in `data` for --json.
      cmd.result = {
        data: res,
        table: {
          snapshot: res.snapshotId,
          restored: res.restored.length,
          recreated: res.recreated.length,
          conflicts: res.conflicts.length,
          newerThanSnapshot: res.newerThanSnapshot.length,
        },
        summary:
          `Restored ${res.restored.length} item(s) from ${res.snapshotId}` +
          (res.recreated.length ? `, re-created ${res.recreated.length}` : "") +
          (res.conflicts.length ? `, skipped ${res.conflicts.length} locked` : "") +
          (res.newerThanSnapshot.length ? `, left ${res.newerThanSnapshot.length} newer item(s) untouched` : "") +
          ".",
      };
    });
}
