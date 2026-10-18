// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Persistent token storage for the CLI.
 *
 * After an interactive SSO login the minted session token is written here so
 * subsequent commands authenticate without re-prompting. Resolution precedence
 * everywhere in the CLI is: explicit `--token` > `CLOUDFS_TOKEN` env > this store.
 *
 * The token is a bearer credential, so the file is written `0600` (owner-only),
 * matching the cloudfsd control-socket posture (filesystem perms are the guard).
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

/** The directory holding CLI credentials (override with `CLOUDFS_CONFIG_DIR`). */
export function configDir(): string {
  if (process.env.CLOUDFS_CONFIG_DIR) return process.env.CLOUDFS_CONFIG_DIR;
  const xdg = process.env.XDG_CONFIG_HOME;
  return xdg ? join(xdg, "cloudfs") : join(homedir(), ".config", "cloudfs");
}

/** Absolute path of the stored-token file. */
export function tokenPath(): string {
  return join(configDir(), "token");
}

/** Persist a session token (writes `0600`). */
export function saveToken(token: string): void {
  const file = tokenPath();
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, token.trim() + "\n", { mode: 0o600 });
  try {
    chmodSync(file, 0o600); // enforce even if the file pre-existed with looser perms
  } catch {
    /* best effort on platforms without chmod */
  }
}

/** Read the stored token, or `null` if none is saved. */
export function loadToken(): string | null {
  const file = tokenPath();
  if (!existsSync(file)) return null;
  try {
    const t = readFileSync(file, "utf8").trim();
    return t || null;
  } catch {
    return null;
  }
}

/** Remove the stored token (used by `auth logout`). Idempotent. */
export function clearToken(): void {
  const file = tokenPath();
  try {
    rmSync(file, { force: true });
  } catch {
    /* ignore */
  }
}
