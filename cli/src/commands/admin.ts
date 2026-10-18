// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Command } from "commander";
import type { Context } from "../context.js";
import type { User } from "../gateway/types.js";
import { requireEnum } from "../util.js";

/** `cloudfs users`, `cloudfs groups`, `cloudfs permissions` — identity & ACL admin (SPEC §4). */
export function registerAdmin(program: Command, ctx: () => Context): void {
  // ----- users -----
  const users = program.command("users").description("manage org members (admin)");
  users
    .command("list")
    .description("list org members")
    .action(async (_opts, cmd) => {
      const list = await ctx().client.usersList();
      cmd.result = { data: list, table: list.map((u) => ({ email: u.email, role: u.role, status: u.status, groups: u.groups.join(",") })) };
    });
  users
    .command("create <email>")
    .description("create a member")
    .option("--role <role>", "owner|admin|space-admin|standard", "standard")
    // FINDING 3: the backend requires a displayName; collect it here (defaults to the
    // email local-part in the client when omitted).
    .option("--name <displayName>", "display name (defaults to the email local-part)")
    .action(async (email: string, opts: { role: User["role"]; name?: string }, cmd) => {
      // B27: validate the role enum (an unknown role would otherwise reach the wire and
      // 400, or be coerced server-side).
      const role = requireEnum("role", opts.role, ["owner", "admin", "space-admin", "standard"] as const);
      const u = await ctx().client.userCreate({ email, role, displayName: opts.name });
      cmd.result = { data: u, summary: `Created ${u.email} (${u.role}).` };
    });
  users
    .command("remove <email>")
    .description("remove a member")
    .action(async (email: string, _opts, cmd) => {
      await ctx().client.userRemove(email);
      cmd.result = { data: { removed: email }, summary: `Removed ${email}.` };
    });

  // ----- groups -----
  const groups = program.command("groups").description("manage groups (admin)");
  groups
    .command("list")
    .description("list groups")
    .action(async (_opts, cmd) => {
      const list = await ctx().client.groupsList();
      cmd.result = { data: list, table: list.map((g) => ({ name: g.name, members: g.members.length })) };
    });
  groups
    .command("create <name>")
    .description("create a group")
    .action(async (name: string, _opts, cmd) => {
      const g = await ctx().client.groupCreate(name);
      cmd.result = { data: g, summary: `Created group ${g.name}.` };
    });
  groups
    .command("add-member <group> <email>")
    .description("add a member to a group")
    .action(async (group: string, email: string, _opts, cmd) => {
      const g = await ctx().client.groupAddMember(group, email);
      cmd.result = { data: g, summary: `Added ${email} to ${group}.` };
    });
  groups
    .command("remove-member <group> <email>")
    .description("remove a member from a group")
    .action(async (group: string, email: string, _opts, cmd) => {
      const g = await ctx().client.groupRemoveMember(group, email);
      cmd.result = { data: g, summary: `Removed ${email} from ${group}.` };
    });

  // ----- permissions (ACLs) -----
  const perms = program.command("permissions").alias("perm").description("folder-granular ACLs (SPEC §4.3)");
  perms
    .command("grant <principal> <path> <level> [filespace]")
    .description("grant access (level: read|read-write|admin). principal: email or group:name")
    .option("--mount-as-root", "confine principal to this folder as their root (RootPoint)")
    .option("--expires <iso>", "optional expiry timestamp (expiring grant)")
    .action(async (principal: string, path: string, level: string, filespace: string | undefined, opts: { mountAsRoot?: boolean; expires?: string }, cmd) => {
      const c = ctx();
      // B27: validate the level enum up front. Pre-fix an invalid level (e.g. "write")
      // was cast and silently coerced to "read" on the wire — a SILENT down-grant.
      const lvl = requireEnum("level", level, ["read", "read-write", "admin"] as const);
      const g = await c.client.permissionGrant({
        filespace: c.filespace(filespace),
        principal,
        path,
        level: lvl,
        mountAsRoot: opts.mountAsRoot,
        expiresAt: opts.expires ?? null,
      });
      cmd.result = { data: g, summary: `Granted ${g.level} on ${g.path} to ${g.principal}.` };
    });
  perms
    .command("revoke <principal> <path> [filespace]")
    .description("revoke a grant")
    .action(async (principal: string, path: string, filespace: string | undefined, _opts, cmd) => {
      const c = ctx();
      await c.client.permissionRevoke({ filespace: c.filespace(filespace), principal, path });
      cmd.result = { data: { revoked: { principal, path } }, summary: `Revoked ${principal} on ${path}.` };
    });
  perms
    .command("list [path] [filespace]")
    .description("list grants (optionally for one path)")
    .action(async (path: string | undefined, filespace: string | undefined, _opts, cmd) => {
      const c = ctx();
      const list = await c.client.permissionList(c.filespace(filespace), path);
      cmd.result = { data: list, table: list.map((g) => ({ principal: g.principal, path: g.path, level: g.level, root: g.mountAsRoot ? "yes" : "", expires: g.expiresAt ?? "never" })) };
    });
}
