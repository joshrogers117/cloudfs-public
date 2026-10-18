// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Command } from "commander";
import type { Context } from "../context.js";
import { parsePositiveInt, requireEnum } from "../util.js";

/** `cloudfs share link create|list|revoke` — guest + direct deep links (SPEC §4.10, R10). */
export function registerShare(program: Command, ctx: () => Context): void {
  const share = program.command("share").description("share links (external guest + internal direct)");
  const link = share.command("link").description("manage share links");

  link
    .command("create <path> [filespace]")
    .description("create a share link for a path")
    .option("--kind <kind>", "link kind: guest | direct", "guest")
    .option("--expires <days>", "expiry in days (guest links)")
    .action(async (path: string, filespace: string | undefined, opts: { kind: "guest" | "direct"; expires?: string }, cmd) => {
      const c = ctx();
      // B27: validate the --kind enum. Pre-fix any non-"direct" value (incl. a typo like
      // "guests") was silently treated as a guest link by shareCreate.
      const kind = requireEnum("--kind", opts.kind, ["guest", "direct"] as const);
      const l = await c.client.shareCreate({
        filespace: c.filespace(filespace),
        path,
        kind,
        // FINDING 9: validate --expires (a NaN day count silently became a null ttl).
        expiresInDays: opts.expires ? parsePositiveInt("--expires", opts.expires) : undefined,
      });
      cmd.result = { data: l, summary: l.url };
    });

  link
    .command("list [filespace]")
    .description("list active share links")
    .action(async (filespace: string | undefined, _opts, cmd) => {
      const c = ctx();
      const list = await c.client.shareList(c.filespace(filespace));
      cmd.result = { data: list, table: list.map((l) => ({ id: l.id, kind: l.kind, path: l.path, expires: l.expiresAt ?? "never", url: l.url })) };
    });

  link
    .command("revoke <id> [filespace]")
    .description("revoke a share link")
    .action(async (id: string, filespace: string | undefined, _opts, cmd) => {
      const c = ctx();
      await c.client.shareRevoke(c.filespace(filespace), id);
      cmd.result = { data: { revoked: id }, summary: `Revoked ${id}.` };
    });
}
