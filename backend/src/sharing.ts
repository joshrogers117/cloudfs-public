// SPDX-License-Identifier: AGPL-3.0-or-later
// sharing.ts — share links: internal `cloudfs://` deep links + external share links.
//
// Two distinct concepts, BOTH from the spec (SPEC §3.7 R10 + §4.3/§4.10):
//
//  1. INTERNAL DEEP LINK ("copy link that opens in the recipient's Finder", R10).
//     A `cloudfs://<space>/<path>` URL. NOT a credential — it carries no access; the
//     recipient must already be a member with an ACL grant. The macOS app's URL-scheme
//     handler resolves it, permission-checks via the gateway, and reveals the item in
//     Finder (NSWorkspace.activateFileViewerSelecting). Pure encode/decode lives here.
//
//  2. EXTERNAL SHARE LINK (Guest Access, §4.3/§4.10 GuestLink).
//     A scoped, expiring, single-folder/file token a NON-member opens in a browser.
//     `internal` (member-only resolve) vs `public` (guest, preview/download only).
//     We mint a random token, store only its hash (like invites.ts), and the gateway
//     redeems it into a short-lived presigned GET at access time (enforcement stays at
//     mint time — the link itself never embeds bucket credentials).
//
// SPLIT for testability + ownership (same as invites.ts): pure link logic up top
// (no DO/env), DO-backed handler at the bottom. No JWT/session crypto here.

import type { OrgDOEnv, AuthedContext, ShareLinkRow } from "./org-do";
import type { Level } from "./permissions";

// ---- 1. internal cloudfs:// deep links (pure) ------------------------------

export interface DeepLinkPayload {
  spaceId: string;
  /** POSIX-style path within the space, e.g. "/ShowA/Edit/timeline.prproj". */
  path: string;
  /** Optional: select-in-Finder hint vs just reveal-folder. */
  select?: boolean;
}

/**
 * Build a `cloudfs://<space>/<url-encoded-path>` deep link. This is an internal
 * navigation aid only — it grants nothing (SPEC §3.7: distinct from guest links).
 */
export function buildDeepLink(p: DeepLinkPayload): string {
  const segments = p.path.split("/").filter(Boolean).map(encodeURIComponent);
  const q = p.select === false ? "?select=0" : "";
  return `cloudfs://${encodeURIComponent(p.spaceId)}/${segments.join("/")}${q}`;
}

/** Parse a `cloudfs://` deep link back into its payload. null if malformed. */
export function parseDeepLink(link: string): DeepLinkPayload | null {
  if (!link.startsWith("cloudfs://")) return null;
  let url: URL;
  try {
    url = new URL(link);
  } catch {
    return null;
  }
  const spaceId = decodeURIComponent(url.hostname);
  if (!spaceId) return null;
  const path =
    "/" +
    url.pathname
      .split("/")
      .filter(Boolean)
      .map((s) => decodeURIComponent(s))
      .join("/");
  const select = url.searchParams.get("select") !== "0";
  return { spaceId, path, select };
}

// ---- 2. external share links (scoped, expiring tokens) ---------------------

export type ShareAudience = "internal" | "public";

export interface ShareLinkRecord {
  id: string;
  orgId: string;
  spaceId: string;
  inodeId: string; // the file or folder being shared
  audience: ShareAudience;
  /** External/public links are preview/download only => "read"; internal can be higher. */
  level: Level;
  tokenHash: string;
  email: string | null; // optional: gate a public link to one recipient (emailed code)
  createdByMemberId: string;
  createdAt: number;
  expiresAt: number;
  revoked: boolean;
}

export interface NewShareToken {
  rawToken: string; // returned ONCE; format `shr_<id>.<secret>`
  shareId: string;
  tokenHash: string;
}

export async function mintShareToken(): Promise<NewShareToken> {
  const shareId = `shr-${crypto.randomUUID()}`;
  const secretBytes = new Uint8Array(32);
  crypto.getRandomValues(secretBytes);
  const secret = toHex(secretBytes);
  const rawToken = `${shareId}.${secret}`;
  const tokenHash = await sha256Hex(rawToken);
  return { rawToken, shareId, tokenHash };
}

export async function parseShareToken(rawToken: string): Promise<{ shareId: string; tokenHash: string } | null> {
  const dot = rawToken.indexOf(".");
  if (dot <= 0) return null;
  const shareId = rawToken.slice(0, dot);
  if (!shareId.startsWith("shr-")) return null;
  return { shareId, tokenHash: await sha256Hex(rawToken) };
}

export type ShareError = "not_found" | "expired" | "revoked" | "token_mismatch";

/** Pure validation of a stored share record against a presented hash + clock. */
export function validateShareLink(
  record: ShareLinkRecord | null,
  presentedHash: string,
  nowMs: number,
): { ok: true } | { ok: false; error: ShareError } {
  if (!record) return { ok: false, error: "not_found" };
  if (record.tokenHash !== presentedHash) return { ok: false, error: "token_mismatch" };
  if (record.revoked) return { ok: false, error: "revoked" };
  if (record.expiresAt <= nowMs) return { ok: false, error: "expired" };
  return { ok: true };
}

export const DEFAULT_SHARE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days (Dana's deliverables example)

// ---- DO-backed operations --------------------------------------------------
// Share-link rows are stored in OrgDO via small RPCs added there. To keep ownership
// clean (no edits to other agents' files) AND avoid bloating OrgDO's interface in
// this pass, we persist share links through a tiny KV-style table accessed by the
// same OrgDO stub using its generic `putInvite`-style methods is NOT appropriate;
// instead the gateway wires these. For the prototype + tests we expose a pure
// in-memory store so sharing.test.ts runs without a DO, and document the DO columns
// needed in multiuser-INTEGRATION.md.

export interface ShareLinkStore {
  put(rec: ShareLinkRecord): void | Promise<void>;
  getByTokenHash(tokenHash: string): ShareLinkRecord | null | Promise<ShareLinkRecord | null>;
  getById(id: string): ShareLinkRecord | null | Promise<ShareLinkRecord | null>;
  setRevoked(id: string): void | Promise<void>;
  listActive(spaceId?: string): ShareLinkRecord[] | Promise<ShareLinkRecord[]>;
}

export interface CreateShareInput {
  spaceId: string;
  inodeId: string;
  audience?: ShareAudience;
  level?: Level;
  email?: string | null;
  ttlMs?: number;
}

export interface CreateShareResult {
  share: ShareLinkRecord;
  rawToken: string;
  /** A browser URL the recipient opens (resolved by the gateway's share endpoint). */
  shareUrl: string;
}

export async function createShareLink(
  store: ShareLinkStore,
  orgId: string,
  createdByMemberId: string,
  input: CreateShareInput,
  baseUrl = "https://share.cloudfs.app",
): Promise<CreateShareResult> {
  const audience = input.audience ?? "public";
  // public/guest links are preview/download only (SPEC §4.3 GuestLink level=read)
  const level: Level = audience === "public" ? "read" : input.level ?? "read";
  const { rawToken, shareId, tokenHash } = await mintShareToken();
  const t = Date.now();
  const share: ShareLinkRecord = {
    id: shareId,
    orgId,
    spaceId: input.spaceId,
    inodeId: input.inodeId,
    audience,
    level,
    tokenHash,
    email: input.email ?? null,
    createdByMemberId,
    createdAt: t,
    expiresAt: t + (input.ttlMs ?? DEFAULT_SHARE_TTL_MS),
    revoked: false,
  };
  await store.put(share);
  return { share, rawToken, shareUrl: `${baseUrl}/s/${encodeURIComponent(rawToken)}` };
}

export interface ResolveShareResult {
  ok: boolean;
  error?: ShareError;
  /** On success, what the gateway should mint a presigned GET for, and at what level. */
  grant?: { spaceId: string; inodeId: string; level: Level; audience: ShareAudience };
}

/**
 * Resolve a presented share token. On success the gateway mints a short-lived
 * presigned GET for the shared object(s) — enforcement stays at mint time (SPEC §4.4);
 * the token never embeds bucket credentials. This function does the validation only.
 */
export async function resolveShareLink(store: ShareLinkStore, rawToken: string): Promise<ResolveShareResult> {
  const parsed = await parseShareToken(rawToken);
  if (!parsed) return { ok: false, error: "not_found" };
  const rec = await store.getByTokenHash(parsed.tokenHash);
  const check = validateShareLink(rec ?? null, parsed.tokenHash, Date.now());
  if (!check.ok) return { ok: false, error: check.error };
  const r = rec!;
  return { ok: true, grant: { spaceId: r.spaceId, inodeId: r.inodeId, level: r.level, audience: r.audience } };
}

export async function revokeShareLink(store: ShareLinkStore, shareId: string): Promise<boolean> {
  const rec = await store.getById(shareId);
  if (!rec || rec.revoked) return false;
  await store.setRevoked(shareId);
  return true;
}

// ---- reference in-memory ShareLinkStore (test fixture; mirrors DO columns) -

export class InMemoryShareLinkStore implements ShareLinkStore {
  private byId = new Map<string, ShareLinkRecord>();

  put(rec: ShareLinkRecord): void {
    this.byId.set(rec.id, rec);
  }
  getById(id: string): ShareLinkRecord | null {
    return this.byId.get(id) ?? null;
  }
  getByTokenHash(tokenHash: string): ShareLinkRecord | null {
    return [...this.byId.values()].find((r) => r.tokenHash === tokenHash) ?? null;
  }
  setRevoked(id: string): void {
    const r = this.byId.get(id);
    if (r) r.revoked = true;
  }
  listActive(spaceId?: string): ShareLinkRecord[] {
    const now = Date.now();
    return [...this.byId.values()].filter(
      (r) => !r.revoked && r.expiresAt > now && (!spaceId || r.spaceId === spaceId),
    );
  }
}

// ---- durable OrgDO-backed ShareLinkStore (production) ----------------------
// ShareLinkRecord and OrgDO's ShareLinkRow are structurally identical, so this
// adapter is a thin pass-through over the DO RPCs added in org-do.ts.
export class OrgDOShareLinkStore implements ShareLinkStore {
  private stub: DurableObjectStub<import("./org-do").OrgDO>;

  constructor(env: OrgDOEnv, orgId: string) {
    this.stub = env.ORG_DO.get(env.ORG_DO.idFromName(orgId));
  }

  async put(rec: ShareLinkRecord): Promise<void> {
    await this.stub.putShareLink(rec as ShareLinkRow);
  }
  async getById(id: string): Promise<ShareLinkRecord | null> {
    return (await this.stub.getShareLinkById(id)) as ShareLinkRecord | null;
  }
  async getByTokenHash(tokenHash: string): Promise<ShareLinkRecord | null> {
    return (await this.stub.getShareLinkByTokenHash(tokenHash)) as ShareLinkRecord | null;
  }
  async setRevoked(id: string): Promise<void> {
    await this.stub.setShareLinkRevoked(id);
  }
  async listActive(spaceId?: string): Promise<ShareLinkRecord[]> {
    return (await this.stub.listActiveShareLinks(spaceId)) as ShareLinkRecord[];
  }
}

/** Convenience: build the durable store for an org (for the gateway to inject). */
export function shareLinkStoreFor(env: OrgDOEnv, orgId: string): ShareLinkStore {
  return new OrgDOShareLinkStore(env, orgId);
}

// ---- HTTP handler ----------------------------------------------------------

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const SHARE_HTTP_STATUS: Record<ShareError, number> = {
  not_found: 404,
  expired: 410,
  revoked: 410,
  token_mismatch: 401,
};

/**
 * Mounted at /v1/orgs/:orgId/shares/** (external links) and /v1/orgs/:orgId/links (deep links).
 *   POST /shares                 create external share (admin/space_admin) -> { rawToken, shareUrl }
 *   GET  /shares                 list active shares (admin)
 *   POST /shares/resolve         PUBLIC: { token } -> grant the gateway will presign
 *   DELETE /shares/:id           revoke (admin)
 *   POST /links                  build an internal cloudfs:// deep link { spaceId, path }
 *
 * `store` is injected (a DO-backed ShareLinkStore in prod; see INTEGRATION for the
 * exact OrgDO columns). `pathParts` is the path AFTER /v1/orgs/:orgId.
 */
export async function handleSharingRequest(
  req: Request,
  store: ShareLinkStore,
  ctx: AuthedContext | null,
  pathParts: string[],
  orgId: string,
): Promise<Response> {
  const resource = pathParts[0];
  const sub = pathParts[1];
  const isAdmin = ctx?.orgRole === "owner" || ctx?.orgRole === "admin" || ctx?.orgRole === "space_admin";

  try {
    // internal deep links — building one needs a session (member) but no admin.
    if (resource === "links" && req.method === "POST") {
      if (!ctx) return json({ error: "forbidden: session required" }, 403);
      const b = (await req.json()) as DeepLinkPayload;
      if (!b.spaceId || !b.path) return json({ error: "spaceId and path required" }, 400);
      return json({ deepLink: buildDeepLink(b) }, 200);
    }

    if (resource === "shares") {
      // PUBLIC resolve — the share token is the credential.
      if (sub === "resolve" && req.method === "POST") {
        const b = (await req.json()) as { token: string };
        if (!b.token) return json({ error: "token required" }, 400);
        const result = await resolveShareLink(store, b.token);
        if (!result.ok) return json({ error: result.error }, SHARE_HTTP_STATUS[result.error!]);
        return json(result, 200);
      }

      if (!isAdmin) return json({ error: "forbidden: admin required" }, 403);

      if (!sub && req.method === "POST") {
        const b = (await req.json()) as CreateShareInput;
        if (!b.spaceId || !b.inodeId) return json({ error: "spaceId and inodeId required" }, 400);
        const out = await createShareLink(store, orgId, ctx!.principalUserId, b);
        return json(out, 201);
      }
      if (!sub && req.method === "GET") {
        const spaceId = new URL(req.url).searchParams.get("spaceId") ?? undefined;
        return json(await store.listActive(spaceId));
      }
      if (sub && req.method === "DELETE") {
        const ok = await revokeShareLink(store, decodeURIComponent(sub));
        return ok ? json({ revoked: true }) : json({ error: "not an active share" }, 404);
      }
    }

    return json({ error: "not found" }, 404);
  } catch (e: any) {
    return json({ error: String(e?.message ?? e) }, 500);
  }
}

// ---- crypto utils (one-way digest only) ------------------------------------

function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return toHex(new Uint8Array(digest));
}
