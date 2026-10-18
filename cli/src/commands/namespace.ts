// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Command } from "commander";
import type { Context } from "../context.js";
import type { Item } from "../gateway/types.js";
import { formatSize, parsePositiveInt } from "../util.js";

/** `cloudfs ls` / `cloudfs stat` / `cloudfs tree`. */
export function registerNamespace(program: Command, ctx: () => Context): void {
  program
    .command("ls [path] [filespace]")
    .description("list a directory in the filespace")
    .action(async (path: string | undefined, filespace: string | undefined, _opts, cmd) => {
      const c = ctx();
      const items = await c.client.list(c.filespace(filespace), path ?? "/");
      cmd.result = {
        data: items,
        table: items.map((it) => ({ name: it.name + (it.isDir ? "/" : ""), size: it.isDir ? "-" : formatSize(it.size), pinned: it.pinned ? "yes" : "", modified: it.modified })),
      };
    });

  program
    .command("stat <path> [filespace]")
    .description("show metadata for a single path")
    .action(async (path: string, filespace: string | undefined, _opts, cmd) => {
      const c = ctx();
      const it = await c.client.stat(c.filespace(filespace), path);
      cmd.result = { data: it, table: { ...it, size: formatSize(it.size) } as unknown as Record<string, unknown> };
    });

  program
    .command("tree [path] [filespace]")
    .description("print the directory tree under a path")
    .option("--depth <n>", "max depth", "3")
    .action(async (path: string | undefined, filespace: string | undefined, opts: { depth: string }, cmd) => {
      const c = ctx();
      const fs = c.filespace(filespace);
      const root = path ?? "/";
      // FINDING 9: a NaN `--depth` made `depth > maxDepth` always false → unbounded
      // recursion. Require a positive integer.
      const maxDepth = parsePositiveInt("--depth", opts.depth);
      const nodes: { path: string; name: string; isDir: boolean; depth: number }[] = [];

      async function walk(p: string, depth: number): Promise<void> {
        if (depth > maxDepth) return;
        const items = await c.client.list(fs, p);
        for (const it of items) {
          nodes.push({ path: it.path, name: it.name, isDir: it.isDir, depth });
          if (it.isDir) await walk(it.path, depth + 1);
        }
      }
      await walk(root, 1);

      const lines = nodes.map((n) => `${"  ".repeat(n.depth - 1)}${n.isDir ? "[d] " : "    "}${n.name}`);
      cmd.result = {
        data: { root, nodes: nodes as unknown as Item[] },
        // Plain text tree for human output:
        table: undefined,
        summary: lines.join("\n"),
      };
    });
}
