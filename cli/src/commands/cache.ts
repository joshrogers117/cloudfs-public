// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Command } from "commander";
import type { Context } from "../context.js";
import { formatSize, parseSize } from "../util.js";

/** `cloudfs cache set-size|set-location|info|pin|unpin|prefetch` — the cache superpower (R9). */
export function registerCache(program: Command, ctx: () => Context): void {
  const cache = program.command("cache").description("local cache: resize, relocate, pin, prefetch");

  cache
    .command("info [filespace]")
    .description("show cache size, usage, pinned bytes, and location")
    .action(async (filespace: string | undefined, _opts, cmd) => {
      const c = ctx();
      const info = await c.client.cacheInfo(c.filespace(filespace));
      cmd.result = {
        data: info,
        table: {
          location: info.location,
          size: formatSize(info.sizeBytes),
          used: formatSize(info.usedBytes),
          pinned: formatSize(info.pinnedBytes),
          max: formatSize(info.maxBytes),
        },
      };
    });

  cache
    .command("set-size <size> [filespace]")
    .description("set the cache size (e.g. 256GiB, 2TB)")
    .action(async (size: string, filespace: string | undefined, _opts, cmd) => {
      const c = ctx();
      const info = await c.client.cacheSetSize(c.filespace(filespace), parseSize(size));
      cmd.result = { data: info, summary: `Cache size set to ${formatSize(info.sizeBytes)}.` };
    });

  cache
    .command("set-location <path> [filespace]")
    .description("relocate the cache directory")
    .action(async (path: string, filespace: string | undefined, _opts, cmd) => {
      const c = ctx();
      const info = await c.client.cacheSetLocation(c.filespace(filespace), path);
      cmd.result = { data: info, summary: `Cache relocated to ${info.location}.` };
    });

  cache
    .command("pin <path> [filespace]")
    .description("pin a path so its blocks stay resident in cache")
    .option("-r, --recursive", "pin recursively")
    .action(async (path: string, filespace: string | undefined, opts: { recursive?: boolean }, cmd) => {
      const c = ctx();
      const res = await c.client.pin(c.filespace(filespace), path, !!opts.recursive);
      cmd.result = { data: res, summary: `Pinned ${res.path}.` };
    });

  cache
    .command("unpin <path> [filespace]")
    .description("unpin a path")
    .option("-r, --recursive", "unpin recursively")
    .action(async (path: string, filespace: string | undefined, opts: { recursive?: boolean }, cmd) => {
      const c = ctx();
      const res = await c.client.unpin(c.filespace(filespace), path, !!opts.recursive);
      cmd.result = { data: res, summary: `Unpinned ${res.path}.` };
    });

  cache
    .command("pin-list [filespace]")
    .alias("pins")
    .description("list pinned paths with cached/total bytes and cache state")
    .action(async (filespace: string | undefined, _opts, cmd) => {
      const c = ctx();
      const pins = await c.client.pinList(c.filespace(filespace));
      cmd.result = {
        data: pins,
        table: pins.map((p) => ({
          path: p.path,
          recursive: p.recursive ? "yes" : "",
          cached: formatSize(p.cachedBytes),
          total: formatSize(p.totalBytes),
          state: p.state,
        })),
      };
    });

  cache
    .command("prefetch <path> [filespace]")
    .alias("prehydrate")
    .description("warm the cache for a path before a job")
    .action(async (path: string, filespace: string | undefined, _opts, cmd) => {
      const c = ctx();
      const res = await c.client.prefetch(c.filespace(filespace), path);
      cmd.result = { data: res, summary: `Queued ${res.queuedBlocks} blocks for prefetch.` };
    });
}
