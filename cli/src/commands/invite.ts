// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Command } from "commander";
import type { Context } from "../context.js";
import type { User } from "../gateway/types.js";
import { parsePositiveInt, requireEnum } from "../util.js";

/** `cloudfs invite create|list|revoke`. */
export function registerInvite(program: Command, ctx: () => Context): void {
  const invite = program.command("invite").description("member invitations");

  invite
    .command("create <email>")
    .description("invite a new member")
    .option("--role <role>", "owner|admin|space-admin|standard", "standard")
    .option("--expires <days>", "invite expiry in days")
    .action(async (email: string, opts: { role: User["role"]; expires?: string }, cmd) => {
      // FINDING 9: validate --expires (a NaN day count silently became a null ttl).
      const expiresInDays = opts.expires ? parsePositiveInt("--expires", opts.expires) : undefined;
      // B27: validate the role enum (unknown role → USAGE, not a wire 400 later).
      const role = requireEnum("role", opts.role, ["owner", "admin", "space-admin", "standard"] as const);
      const inv = await ctx().client.inviteCreate({ email, role, expiresInDays });
      cmd.result = { data: inv, summary: inv.url };
    });

  invite
    .command("list")
    .description("list invitations")
    .action(async (_opts, cmd) => {
      const list = await ctx().client.inviteList();
      cmd.result = { data: list, table: list.map((i) => ({ id: i.id, email: i.email, role: i.role, status: i.status, expires: i.expiresAt ?? "never" })) };
    });

  invite
    .command("revoke <id>")
    .description("revoke a pending invitation")
    .action(async (id: string, _opts, cmd) => {
      await ctx().client.inviteRevoke(id);
      cmd.result = { data: { revoked: id }, summary: `Revoked invite ${id}.` };
    });
}
