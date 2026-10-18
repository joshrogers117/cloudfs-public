// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Command } from "commander";
import type { Context } from "../context.js";

/** `cloudfs filespace connect|disconnect|list|status|create`. */
export function registerFilespace(program: Command, ctx: () => Context): void {
  const fs = program.command("filespace").alias("fs").description("manage filespaces (mounted namespaces)");

  fs.command("list")
    .description("list filespaces visible to the caller")
    .action(async (_opts, cmd) => {
      const c = ctx();
      const list = await c.client.listFilespaces();
      cmd.result = {
        data: list,
        table: list.map((f) => ({ id: f.id, name: f.name, status: f.status, role: f.role ?? "", mount: f.mountPath ?? "-" })),
      };
    });

  fs.command("status [filespace]")
    .description("show status for one filespace (default: --filespace)")
    .action(async (filespace: string | undefined, _opts, cmd) => {
      const c = ctx();
      const f = await c.client.getFilespace(c.filespace(filespace));
      cmd.result = { data: f, table: f as unknown as Record<string, unknown> };
    });

  fs.command("create <name>")
    .description("create a new filespace")
    .option("--bucket <uri>", "backing bucket URI (e.g. r2://my-bucket)")
    .action(async (name: string, opts: { bucket?: string }, cmd) => {
      const c = ctx();
      const f = await c.client.createFilespace({ name, bucket: opts.bucket });
      cmd.result = { data: f, summary: `Created filespace ${f.id}.` };
    });

  fs.command("connect [filespace]")
    .description("connect (attach metadata + start engine) for a filespace")
    .action(async (filespace: string | undefined, _opts, cmd) => {
      const c = ctx();
      const f = await c.client.connectFilespace(c.filespace(filespace));
      cmd.result = { data: f, summary: `Connected ${f.id}.` };
    });

  fs.command("disconnect [filespace]")
    .description("disconnect a filespace")
    .action(async (filespace: string | undefined, _opts, cmd) => {
      const c = ctx();
      const f = await c.client.disconnectFilespace(c.filespace(filespace));
      cmd.result = { data: f, summary: `Disconnected ${f.id}.` };
    });
}
