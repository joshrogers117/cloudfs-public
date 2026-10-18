// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Command } from "commander";
import type { Context } from "../context.js";
import { printNdjson } from "../output.js";
import { parsePositiveInt } from "../util.js";

/**
 * `cloudfs activity` — bounded recent change log (point-in-time).
 * `cloudfs events --stream` — live NDJSON stream of change/lock/upload events
 * (SPEC §3.8 event streaming), so an ingest watcher can trigger work instantly.
 */
export function registerEvents(program: Command, ctx: () => Context): void {
  program
    .command("activity [filespace]")
    .description("show recent change/lock/upload activity")
    .option("--limit <n>", "max events", "50")
    .option("--path <path>", "filter under a path")
    .action(async (filespace: string | undefined, opts: { limit: string; path?: string }, cmd) => {
      const c = ctx();
      // FINDING 9: validate --limit (a NaN limit broke the bounded fetch loop).
      const limit = parsePositiveInt("--limit", opts.limit);
      const events = await c.client.activity({ filespace: c.filespace(filespace), limit });
      const filtered = opts.path ? events.filter((e) => e.path.startsWith(opts.path!)) : events;
      cmd.result = { data: filtered, table: filtered.map((e) => ({ seq: e.seq, type: e.type, path: e.path, actor: e.actor, ts: e.ts })) };
    });

  program
    .command("events [filespace]")
    .description("stream change/lock/upload events as NDJSON")
    .option("--stream", "stream continuously (default for events)", true)
    .option("--path <path>", "filter under a path")
    .action(async (filespace: string | undefined, opts: { stream?: boolean; path?: string }, cmd) => {
      const c = ctx();
      const fs = c.filespace(filespace);
      const controller = new AbortController();
      const onSig = () => controller.abort();
      process.once("SIGINT", onSig);
      process.once("SIGTERM", onSig);

      const collected: unknown[] = [];
      try {
        for await (const e of c.client.events({ filespace: fs, path: opts.path, signal: controller.signal })) {
          // Events are inherently NDJSON; one line per event regardless of --output.
          if (c.output.format === "json" || !c.output.quiet) printNdjson(e, c.output);
          collected.push(e);
        }
      } finally {
        process.removeListener("SIGINT", onSig);
        process.removeListener("SIGTERM", onSig);
      }
      // Mark as already-printed so the runner does not double-emit.
      cmd.result = { data: collected, alreadyPrinted: true };
    });
}
