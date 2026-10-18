// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * WIRE-CONTRACT TESTS — close the gap the 99 mock-seam tests miss.
 *
 * Every existing CLI test injects a MockGatewayClient, so it bypasses BOTH the real
 * token wiring AND the live wire contract (the field names/URLs/headers the backend
 * actually reads). These tests drive the REAL HttpGatewayClient with an injected
 * `fetch` mock that captures method/url/query/headers/body, and assert the emitted
 * request matches what the backend reads:
 *
 *   - backend/src/org-do.ts registerSpace : { name, bucketProvider, bucketName, keyPrefix }
 *   - backend/src/users.ts (create)       : requires { email, displayName }
 *   - backend/src/users.ts (group add)    : body { userId }
 *   - backend/src/users.ts (group remove) : ?userId= query
 *   - backend/src/sharing.ts (create)     : { spaceId, inodeId, ttlMs }
 *   - backend/src/sharing.ts (list)       : ?spaceId=
 *   - backend/src/invites.ts (create)     : { email, role, ttlMs } -> { invite, rawToken }
 *
 * Several of these FAIL against the pre-fix code (noted per `it`).
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { HttpGatewayClient, type FetchLike } from "../src/gateway/http.js";
import { ExitCode } from "../src/exit-codes.js";
import { tokenPath } from "../src/auth/token-store.js";
import { makeFetch, fakeToken, type Handler } from "./fetch-mock.js";
import { runCli, runCliWith } from "./helpers.js";

const TOKEN = fakeToken({ sub: "ci-bot@svc", typ: "service", org: "studio", scp: ["fs:read", "fs:write", "fs:admin"], exp: 4102444800 });
const BASE = "https://gw.cloudfs.example";

function client(routes: Record<string, Handler>, token = TOKEN) {
  const mf = makeFetch(routes);
  const c = new HttpGatewayClient({ baseUrl: BASE, token, fetch: mf.fetch });
  return { c, mf };
}

// ─────────────────────────────────────────────────────────────────────────────
// FINDING 2 — filespace create sends bucketProvider/bucketName/keyPrefix
// (PRE-FIX: sent { name, bucket } → FAILS these assertions)
// ─────────────────────────────────────────────────────────────────────────────
describe("FINDING 2 — filespace create → registerSpace fields", () => {
  it("parses provider://name/prefix into bucketProvider/bucketName/keyPrefix", async () => {
    const { c, mf } = client({ "POST /v1/orgs/studio/spaces": { status: 201, json: { id: "fs-1", name: "Edit" } } });
    await c.createFilespace({ name: "Edit", bucket: "r2://studio-media/team/edit" });
    const req = mf.last();
    expect(req.method).toBe("POST");
    expect(req.path).toBe("/v1/orgs/studio/spaces");
    expect(req.body).toEqual({ name: "Edit", bucketProvider: "r2", bucketName: "studio-media", keyPrefix: "team/edit" });
    expect(req.body.bucket).toBeUndefined(); // the old single-field shape is gone
  });

  it("defaults keyPrefix to '' when the URI has no path", async () => {
    const { c, mf } = client({ "POST /v1/orgs/studio/spaces": { status: 201, json: { id: "fs-2", name: "A" } } });
    await c.createFilespace({ name: "A", bucket: "s3://my-bucket" });
    expect(mf.last().body).toEqual({ name: "A", bucketProvider: "s3", bucketName: "my-bucket", keyPrefix: "" });
  });

  it("rejects a missing/unparseable --bucket with a USAGE error (no malformed space)", async () => {
    const { c, mf } = client({ "POST /v1/orgs/studio/spaces": { status: 201, json: {} } });
    await expect(c.createFilespace({ name: "A" })).rejects.toMatchObject({ code: ExitCode.USAGE });
    await expect(c.createFilespace({ name: "A", bucket: "not-a-uri" })).rejects.toMatchObject({ code: ExitCode.USAGE });
    expect(mf.requests).toHaveLength(0); // never hit the network with a bad bucket
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// FINDING 3 — users create includes displayName
// (PRE-FIX: sent { email, role } → backend 400s "email and displayName required")
// ─────────────────────────────────────────────────────────────────────────────
describe("FINDING 3 — users create → displayName required", () => {
  it("defaults displayName to the email local-part", async () => {
    const { c, mf } = client({ "POST /v1/orgs/studio/users": { status: 201, json: { id: "usr-1", email: "ed@studio.tv", role: "standard" } } });
    await c.userCreate({ email: "ed@studio.tv", role: "standard" });
    expect(mf.last().body).toEqual({ email: "ed@studio.tv", role: "standard", displayName: "ed" });
  });

  it("uses an explicit displayName when given", async () => {
    const { c, mf } = client({ "POST /v1/orgs/studio/users": { status: 201, json: { id: "usr-2", email: "x@y.tv", role: "admin" } } });
    await c.userCreate({ email: "x@y.tv", role: "admin", displayName: "Ed Editor" });
    expect(mf.last().body).toMatchObject({ displayName: "Ed Editor" });
  });

  it("through the CLI, --name flows into displayName", async () => {
    const { c, mf } = client({ "POST /v1/orgs/studio/users": { status: 201, json: { id: "usr-3", email: "a@b.tv", role: "standard" } } });
    const r = await runCliWith(["--json", "users", "create", "a@b.tv", "--name", "Alice B"], c);
    expect(r.code).toBe(0);
    expect(mf.last().body).toMatchObject({ email: "a@b.tv", displayName: "Alice B" });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// FINDING 4 — group add/remove key off userId (resolved from email)
// (PRE-FIX: add sent { email }; remove put the member in the URL path → no-op)
// ─────────────────────────────────────────────────────────────────────────────
describe("FINDING 4 — group membership keyed by userId", () => {
  const usersRoute: Handler = { json: [{ id: "usr-42", email: "ed@studio.tv", role: "standard" }] };

  it("add-member resolves email → userId and posts { userId }", async () => {
    const { c, mf } = client({
      "GET /v1/orgs/studio/users": usersRoute,
      "POST /v1/orgs/studio/groups/editors/members": { json: { ok: true } },
    });
    await c.groupAddMember("editors", "ed@studio.tv");
    const post = mf.requests.find((r) => r.method === "POST")!;
    expect(post.path).toBe("/v1/orgs/studio/groups/editors/members");
    expect(post.body).toEqual({ userId: "usr-42" });
  });

  it("remove-member sends ?userId= on the DELETE (not the member in the path)", async () => {
    const { c, mf } = client({
      "GET /v1/orgs/studio/users": usersRoute,
      "DELETE /v1/orgs/studio/groups/editors/members": { json: { ok: true } },
    });
    await c.groupRemoveMember("editors", "ed@studio.tv");
    const del = mf.requests.find((r) => r.method === "DELETE")!;
    expect(del.path).toBe("/v1/orgs/studio/groups/editors/members"); // member NOT in the path
    expect(del.query.userId).toBe("usr-42");
  });

  it("passes a usr-<id> straight through without a lookup", async () => {
    const { c, mf } = client({ "POST /v1/orgs/studio/groups/editors/members": { json: { ok: true } } });
    await c.groupAddMember("editors", "usr-99");
    expect(mf.requests.every((r) => r.path !== "/v1/orgs/studio/users")).toBe(true); // no directory list
    expect(mf.last().body).toEqual({ userId: "usr-99" });
  });

  it("an unknown email is a NOT_FOUND error, not a silent no-op", async () => {
    const { c } = client({ "GET /v1/orgs/studio/users": { json: [{ id: "usr-1", email: "someone@else.tv" }] } });
    await expect(c.groupAddMember("editors", "ghost@studio.tv")).rejects.toMatchObject({ code: ExitCode.NOT_FOUND });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// FINDING 4 (userRemove variant) — users remove resolves email → usr-id
// (PRE-FIX: DELETE carried the EMAIL → backend keyed setUserStatus off it, matched
//  zero rows, the user stayed active and offboarding was a silent no-op while the
//  CLI printed "Removed". The DELETE must carry the resolved usr-<id>.)
// ─────────────────────────────────────────────────────────────────────────────
describe("FINDING 4 — users remove keyed by userId (not email)", () => {
  const usersRoute: Handler = { json: [{ id: "usr-42", email: "ed@studio.tv", role: "standard" }] };

  it("resolves email → userId and DELETEs /users/<usr-id> (NOT the email)", async () => {
    const { c, mf } = client({
      "GET /v1/orgs/studio/users": usersRoute,
      "DELETE /v1/orgs/studio/users/usr-42": { json: { id: "usr-42", status: "deprovisioned" } },
    });
    await c.userRemove("ed@studio.tv");
    const del = mf.requests.find((r) => r.method === "DELETE")!;
    expect(del.path).toBe("/v1/orgs/studio/users/usr-42"); // the usr-<id>, not the email
    expect(del.path).not.toContain("ed@studio.tv");
    expect(del.path).not.toContain(encodeURIComponent("ed@studio.tv"));
  });

  it("an unknown email is a NOT_FOUND error, not a false 'Removed'", async () => {
    const { c, mf } = client({ "GET /v1/orgs/studio/users": { json: [{ id: "usr-1", email: "someone@else.tv" }] } });
    await expect(c.userRemove("ghost@studio.tv")).rejects.toMatchObject({ code: ExitCode.NOT_FOUND });
    expect(mf.requests.every((r) => r.method !== "DELETE")).toBe(true); // never deprovisioned anyone
  });

  it("passes a usr-<id> straight through without a directory lookup", async () => {
    const { c, mf } = client({ "DELETE /v1/orgs/studio/users/usr-99": { json: { id: "usr-99", status: "deprovisioned" } } });
    await c.userRemove("usr-99");
    expect(mf.requests.every((r) => r.path !== "/v1/orgs/studio/users")).toBe(true); // no directory list
    expect(mf.last().path).toBe("/v1/orgs/studio/users/usr-99");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// FINDING 5 + 6 — share create { spaceId, inodeId, ttlMs }; list ?spaceId=
// (PRE-FIX: create sent { space, path, expiresInDays }; list used ?space=)
// ─────────────────────────────────────────────────────────────────────────────
describe("FINDING 5/6 — share create + list wire shape", () => {
  it("create maps filespace→spaceId, path→inodeId, days→ttlMs", async () => {
    // Audit B17/B28: ids are opaque; pass one directly so resolvePathToId forwards it
    // without a namespace walk and this test stays focused on the share-create wire body.
    const { c, mf } = client({
      "POST /v1/orgs/studio/shares": { status: 201, json: { share: { id: "shr-1", spaceId: "active-edit", inodeId: "ino-clip", expiresAt: 1_900_000_000_000, createdByMemberId: "usr-1", createdAt: 1_700_000_000_000 }, rawToken: "shr-1.secret", shareUrl: "https://share.cloudfs.app/s/shr-1.secret" } },
    });
    await c.shareCreate({ filespace: "active-edit", path: "ino-clip", kind: "guest", expiresInDays: 5 });
    const req = mf.last();
    expect(req.method).toBe("POST");
    expect(req.path).toBe("/v1/orgs/studio/shares");
    expect(req.body).toEqual({ spaceId: "active-edit", inodeId: "ino-clip", ttlMs: 5 * 86_400_000 });
    expect(req.body.space).toBeUndefined();
    expect(req.body.expiresInDays).toBeUndefined();
  });

  it("create reads id/url from the nested { share, shareUrl } envelope (FINDING 7 variant)", async () => {
    const { c } = client({
      "POST /v1/orgs/studio/shares": { status: 201, json: { share: { id: "shr-7", inodeId: "ino-showa", expiresAt: 1_900_000_000_000 }, rawToken: "tok", shareUrl: "https://share.cloudfs.app/s/tok" } },
    });
    const link = await c.shareCreate({ filespace: "active-edit", path: "ino-showa", kind: "guest" });
    expect(link.id).toBe("shr-7");
    expect(link.url).toBe("https://share.cloudfs.app/s/tok");
    expect(link.expiresAt).not.toBeNull(); // epoch-ms normalized to ISO
  });

  it("list filters on ?spaceId=, not ?space=", async () => {
    const { c, mf } = client({ "GET /v1/orgs/studio/shares": { json: [] } });
    await c.shareList("active-edit");
    expect(mf.last().query.spaceId).toBe("active-edit");
    expect(mf.last().query.space).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// FINDING 7 — invite create: ttlMs body + read { invite, rawToken }
// (PRE-FIX: sent expiresInDays; read raw.id/url/token → empty)
// ─────────────────────────────────────────────────────────────────────────────
describe("FINDING 7 — invite create wire shape + response nesting", () => {
  it("sends ttlMs (not expiresInDays)", async () => {
    const { c, mf } = client({
      "POST /v1/orgs/studio/invites": { status: 201, json: { invite: { id: "inv-1", email: "new@studio.tv", role: "standard", status: "pending", expiresAt: 1_900_000_000_000 }, rawToken: "inv-1.secret" } },
    });
    await c.inviteCreate({ email: "new@studio.tv", role: "standard", expiresInDays: 3 });
    const req = mf.last();
    expect(req.body).toEqual({ email: "new@studio.tv", role: "standard", ttlMs: 3 * 86_400_000 });
    expect(req.body.expiresInDays).toBeUndefined();
  });

  it("reads id/email/expiry from raw.invite.* and the credential from raw.rawToken", async () => {
    const { c } = client({
      "POST /v1/orgs/studio/invites": { status: 201, json: { invite: { id: "inv-7", email: "new@studio.tv", role: "admin", status: "pending", expiresAt: 1_900_000_000_000 }, rawToken: "inv-7.thesecret" } },
    });
    const inv = await c.inviteCreate({ email: "new@studio.tv", role: "admin" });
    expect(inv.id).toBe("inv-7");
    expect(inv.email).toBe("new@studio.tv");
    expect(inv.role).toBe("admin");
    expect(inv.url).toBe("inv-7.thesecret"); // the raw token is the redeemable credential
    expect(inv.expiresAt).not.toBeNull();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// FINDING 8 — request timeout aborts → NETWORK_ERROR
// ─────────────────────────────────────────────────────────────────────────────
describe("FINDING 8 — request timeout maps to NETWORK_ERROR", () => {
  // A fetch that never resolves until its signal aborts (a hung gateway).
  const hungFetch: FetchLike = (_url, init) =>
    new Promise((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
    });

  it("a hung gateway is aborted after the timeout and surfaces NETWORK_ERROR", async () => {
    const c = new HttpGatewayClient({ baseUrl: BASE, token: TOKEN, fetch: hungFetch, requestTimeoutMs: 20 });
    await expect(c.listFilespaces()).rejects.toMatchObject({ code: ExitCode.NETWORK_ERROR });
  });

  it("a fast gateway under the timeout still succeeds", async () => {
    const { c } = client({ "GET /v1/orgs/studio/spaces": { json: { spaces: [] } } });
    await expect(c.listFilespaces()).resolves.toEqual([]);
  });

  it("the timeout is overridable via CLOUDFS_REQUEST_TIMEOUT_MS", async () => {
    const prev = process.env.CLOUDFS_REQUEST_TIMEOUT_MS;
    process.env.CLOUDFS_REQUEST_TIMEOUT_MS = "15";
    try {
      const c = new HttpGatewayClient({ baseUrl: BASE, token: TOKEN, fetch: hungFetch });
      await expect(c.listFilespaces()).rejects.toMatchObject({ code: ExitCode.NETWORK_ERROR });
    } finally {
      if (prev === undefined) delete process.env.CLOUDFS_REQUEST_TIMEOUT_MS;
      else process.env.CLOUDFS_REQUEST_TIMEOUT_MS = prev;
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// FINDING 1 — auth login --token VALIDATES + SAVES the subcommand token
// (PRE-FIX: the subcommand token never reached the client; login probed only the
//  PUBLIC /v1/health, so a bad token "succeeded" and was saved unverified)
// ─────────────────────────────────────────────────────────────────────────────
describe("FINDING 1 — auth login --token validates the subcommand token", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "cfs-login-"));
    process.env.CLOUDFS_CONFIG_DIR = dir;
  });
  afterEach(() => {
    delete process.env.CLOUDFS_CONFIG_DIR;
    rmSync(dir, { recursive: true, force: true });
  });

  it("login() probes an AUTHENTICATED route (not public /v1/health)", async () => {
    const { c, mf } = client({ "GET /v1/orgs/studio/users": { json: [] } });
    await c.login({ token: TOKEN, sso: false });
    const paths = mf.requests.map((r) => r.path);
    expect(paths).toContain("/v1/orgs/studio/users");
    expect(paths).not.toContain("/v1/health"); // health is public → proves nothing
    expect(mf.last().headers.authorization).toBe(`Bearer ${TOKEN}`);
  });

  it("a VALID --token validates and is saved to the token store", async () => {
    const { c } = client({ "GET /v1/orgs/studio/users": { json: [{ id: "usr-1", email: "ci-bot@svc" }] } });
    const r = await runCliWith(["--json", "auth", "login", "--token", TOKEN], c);
    expect(r.code).toBe(0);
    expect(existsSync(tokenPath())).toBe(true);
    expect(readFileSync(tokenPath(), "utf8").trim()).toBe(TOKEN);
  });

  it("a BAD --token (401 bad_signature) exits non-zero and is NOT saved", async () => {
    const { c } = client({ "GET /v1/orgs/studio/users": { status: 401, json: { error: "bad_signature" } } });
    const r = await runCliWith(["--json", "auth", "login", "--token", TOKEN], c);
    expect(r.code).not.toBe(0);
    // A 401 maps to the auth-failure family (NOT_AUTHENTICATED 10 per http-errors.ts;
    // `expired` → TOKEN_EXPIRED 12). The contract for FINDING 1 is non-zero + no save.
    expect([ExitCode.NOT_AUTHENTICATED, ExitCode.AUTH_FAILED, ExitCode.TOKEN_EXPIRED]).toContain(r.code);
    expect(existsSync(tokenPath())).toBe(false); // unverified token never persisted
  });

  it("a 403 (token lacks access) also exits non-zero and is NOT saved", async () => {
    const { c } = client({ "GET /v1/orgs/studio/users": { status: 403, json: { error: "forbidden" } } });
    const r = await runCliWith(["--json", "auth", "login", "--token", TOKEN], c);
    expect(r.code).toBe(ExitCode.PERMISSION_DENIED);
    expect(existsSync(tokenPath())).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// FINDING 9 — unvalidated Number() flags throw USAGE (no busy-loop / null ttl)
// ─────────────────────────────────────────────────────────────────────────────
describe("FINDING 9 — numeric flags validated as USAGE errors", () => {
  const authedMock = { authenticated: true } as const;

  it("tree --depth=abc throws USAGE (was unbounded recursion)", async () => {
    const r = await runCli(["--json", "tree", "/", "active-edit", "--depth", "abc"], authedMock);
    expect(r.code).toBe(ExitCode.USAGE);
  });

  it("wait --timeout=NaN throws USAGE (was infinite wait)", async () => {
    const r = await runCli(["--json", "wait", "/ShowA", "active-edit", "--timeout", "abc"], authedMock);
    expect(r.code).toBe(ExitCode.USAGE);
  });

  it("wait --interval=0 throws USAGE (was zero-delay hammer)", async () => {
    const r = await runCli(["--json", "wait", "/ShowA", "active-edit", "--interval", "0"], authedMock);
    expect(r.code).toBe(ExitCode.USAGE);
  });

  it("activity --limit=NaN throws USAGE", async () => {
    const r = await runCli(["--json", "activity", "active-edit", "--limit", "nope"], authedMock);
    expect(r.code).toBe(ExitCode.USAGE);
  });

  it("share link create --expires=NaN throws USAGE (was a null ttl)", async () => {
    const r = await runCli(["--json", "share", "link", "create", "/ShowA", "active-edit", "--expires", "soon"], authedMock);
    expect(r.code).toBe(ExitCode.USAGE);
  });

  it("invite create --expires=NaN throws USAGE", async () => {
    const r = await runCli(["--json", "invite", "create", "new@studio.tv", "--expires", "later"], authedMock);
    expect(r.code).toBe(ExitCode.USAGE);
  });

  it("valid numeric flags still work (tree --depth=2)", async () => {
    const r = await runCli(["--json", "tree", "/", "active-edit", "--depth", "2"], authedMock);
    expect(r.code).toBe(0);
  });
});
