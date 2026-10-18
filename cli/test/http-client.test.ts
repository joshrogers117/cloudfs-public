// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { HttpGatewayClient, EXPECTED_API_VERSION } from "../src/gateway/http.js";
import { ExitCode } from "../src/exit-codes.js";
import { makeFetch, fakeToken, type Handler } from "./fetch-mock.js";
import { runCliWith } from "./helpers.js";

const TOKEN = fakeToken({ sub: "ci-bot@svc", typ: "service", org: "studio", scp: ["fs:read", "fs:write", "fs:admin"], exp: 4102444800 });
const BASE = "https://gw.cloudfs.example";

function client(routes: Record<string, Handler>) {
  const mf = makeFetch(routes);
  // These suites assert request SHAPE + error→exit-code MAPPING, not retry behavior
  // (which has its own describe block with an injected sleeper). Disable retries here so a
  // transient-status case maps once, deterministically, with no real backoff wait.
  const c = new HttpGatewayClient({ baseUrl: BASE, token: TOKEN, fetch: mf.fetch, maxRetries: 0 });
  return { c, mf };
}

describe("HttpGatewayClient — request shape (API.md)", () => {
  it("sends the bearer token and hits /v1/orgs/:org/spaces for filespace list", async () => {
    const { c, mf } = client({
      "GET /v1/orgs/studio/spaces": { json: { spaces: [{ id: "active-edit", name: "Active Edit", status: "connected", role: "admin" }] } },
    });
    const list = await c.listFilespaces();
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ id: "active-edit", name: "Active Edit", status: "connected" });
    const req = mf.last();
    expect(req.method).toBe("GET");
    expect(req.path).toBe("/v1/orgs/studio/spaces");
    expect(req.headers.authorization).toBe(`Bearer ${TOKEN}`);
  });

  it("maps a CLI path to the items?parent= inode id and sets content-type only on bodies", async () => {
    const { c, mf } = client({
      "GET /v1/filespaces/active-edit/items": { json: { items: [{ id: "ShowA", parent: "root", name: "ShowA", isDir: true, size: 0 }], cursor: null } },
    });
    await c.list("active-edit", "/");
    const req = mf.last();
    expect(req.path).toBe("/v1/filespaces/active-edit/items");
    expect(req.query.parent).toBe("root");
    expect(req.query.limit).toBe("500");
    expect(req.headers["content-type"]).toBeUndefined(); // GET carries no content-type
  });

  it("drains opaque cursor pagination for directory listings", async () => {
    let calls = 0;
    const { c, mf } = client({
      "GET /v1/filespaces/active-edit/items": (req) => {
        calls++;
        if (!req.query.cursor) {
          return { json: { items: [{ id: "a", parent: "root", name: "a", isDir: false, size: 1 }], cursor: "b64-page2" } };
        }
        return { json: { items: [{ id: "b", parent: "root", name: "b", isDir: false, size: 2 }], cursor: null } };
      },
    });
    const items = await c.list("active-edit", "/");
    expect(items.map((i) => i.name)).toEqual(["a", "b"]);
    expect(calls).toBe(2);
    expect(mf.requests[1].query.cursor).toBe("b64-page2"); // opaque cursor echoed back
  });

  it("posts a grant with edit level + group principal split (read-write -> edit)", async () => {
    // Audit B17/B28: ids are opaque, so the CLI resolves the path → opaque id by walking
    // the namespace (GET /items?parent=root) before POSTing the grant against the resolved id.
    const { c, mf } = client({
      "GET /v1/filespaces/active-edit/items": { json: { items: [{ id: "ino-ShowA", parent: "root", name: "ShowA", isDir: true, size: 0 }], cursor: null } },
      "POST /v1/filespaces/active-edit/grants": { status: 201, json: { id: "grant-1" } },
    });
    await c.permissionGrant({ filespace: "active-edit", principal: "group:editors", path: "/ShowA", level: "read-write", mountAsRoot: true });
    const req = mf.last();
    expect(req.method).toBe("POST");
    expect(req.body).toMatchObject({ inodeId: "ino-ShowA", principalType: "group", principalId: "editors", level: "edit", mountAsRoot: true });
  });

  it("synthesizes change events from the change feed (numeric since cursor)", async () => {
    let calls = 0;
    const { c, mf } = client({
      "GET /v1/filespaces/active-edit/changes": (req) => {
        calls++;
        if (!req.query.since) {
          return { json: { anchor: 7, items: [{ id: "ShowA/clip.mov", parent: "ShowA", name: "clip.mov", isDir: false, size: 10, updatedSeq: 5 }], cursor: 5 } };
        }
        return { json: { anchor: 7, items: [{ id: "ShowA/x", parent: "ShowA", name: "x", isDir: false, size: 1, updatedSeq: 7, deleted: true }], cursor: null } };
      },
    });
    const events: any[] = [];
    for await (const e of c.events({ filespace: "active-edit" })) events.push(e);
    expect(events.map((e) => e.type)).toEqual(["modify", "delete"]);
    expect(calls).toBe(2);
    expect(mf.requests[1].query.since).toBe("5"); // numeric cursor echoed as ?since=
  });

  it("authStatus decodes claims from the JWS payload without a network call", async () => {
    const { c, mf } = client({});
    const status = await c.authStatus();
    expect(status).toMatchObject({ authenticated: true, principal: "ci-bot@svc", kind: "service-account", org: "studio" });
    expect(status.scopes).toContain("fs:admin");
    expect(mf.requests).toHaveLength(0);
  });

  it("engine-only operations fail with ENGINE_UNAVAILABLE (not a wrong success)", async () => {
    const { c } = client({});
    await expect(c.cacheInfo()).rejects.toMatchObject({ code: ExitCode.ENGINE_UNAVAILABLE });
    await expect(c.flush()).rejects.toMatchObject({ code: ExitCode.ENGINE_UNAVAILABLE });
    await expect(c.mount()).rejects.toMatchObject({ code: ExitCode.ENGINE_UNAVAILABLE });
  });

  it("health() probes /v1/health (no auth) and reports a matching wire version as compatible", async () => {
    const { c, mf } = client({
      "GET /v1/health": { json: { ok: true, apiVersion: EXPECTED_API_VERSION } },
    });
    const h = await c.health();
    expect(h).toMatchObject({ ok: true, apiVersion: EXPECTED_API_VERSION, expectedApiVersion: EXPECTED_API_VERSION, compatible: true });
    expect(mf.last().path).toBe("/v1/health");
    expect(mf.last().headers.authorization).toBe(`Bearer ${TOKEN}`); // health probe still carries the token harmlessly
  });

  it("health() flags a major wire-version mismatch as incompatible (skew detection)", async () => {
    const { c } = client({
      "GET /v1/health": { json: { ok: true, apiVersion: EXPECTED_API_VERSION + 1 } },
    });
    const h = await c.health();
    expect(h.apiVersion).toBe(EXPECTED_API_VERSION + 1);
    expect(h.compatible).toBe(false);
  });

  it("health() treats a pre-handshake backend (no apiVersion) as best-effort compatible", async () => {
    const { c } = client({
      "GET /v1/health": { json: { ok: true } },
    });
    const h = await c.health();
    expect(h.apiVersion).toBeNull();
    expect(h.compatible).toBe(true);
  });
});

describe("HttpGatewayClient — transient retry + backoff (B27)", () => {
  function retryClient(routes: Record<string, Handler>, maxRetries = 3) {
    const mf = makeFetch(routes);
    const slept: number[] = [];
    const c = new HttpGatewayClient({
      baseUrl: BASE,
      token: TOKEN,
      fetch: mf.fetch,
      maxRetries,
      sleep: async (ms) => { slept.push(ms); }, // never actually wait
    });
    return { c, mf, slept };
  }

  it("retries an idempotent GET on 503 and succeeds, with exponential backoff", async () => {
    let n = 0;
    const { c, mf, slept } = retryClient({
      "GET /v1/orgs/studio/spaces": () => {
        n++;
        if (n < 3) return { status: 503, json: { error: "unavailable" } };
        return { json: { spaces: [{ id: "active-edit", name: "AE", status: "connected", role: "admin" }] } };
      },
    });
    const list = await c.listFilespaces();
    expect(list).toHaveLength(1);
    expect(n).toBe(3); // two failures + one success
    expect(mf.requests).toHaveLength(3);
    expect(slept).toEqual([250, 500]); // exponential schedule (no Retry-After)
  });

  it("honors a Retry-After header instead of the backoff schedule", async () => {
    let n = 0;
    const { c, slept } = retryClient({
      "GET /v1/orgs/studio/spaces": () => {
        n++;
        if (n === 1) return { status: 429, json: { error: "rate_limited" }, headers: { "retry-after": "2" } };
        return { json: { spaces: [] } };
      },
    });
    await c.listFilespaces();
    expect(slept).toEqual([2000]); // 2s from Retry-After, not the 250ms base
  });

  it("does NOT retry a non-idempotent POST (no double-apply)", async () => {
    let n = 0;
    const { c, mf } = retryClient({
      "POST /v1/filespaces/active-edit/grants": () => {
        n++;
        return { status: 503, json: { error: "unavailable" } };
      },
    });
    await expect(
      c.permissionGrant({ filespace: "active-edit", principal: "x@y", path: "ino-ShowA", level: "read" }),
    ).rejects.toMatchObject({ code: ExitCode.GATEWAY_ERROR });
    expect(n).toBe(1); // POST attempted exactly once
    expect(mf.requests).toHaveLength(1);
  });

  it("gives up after maxRetries and surfaces the mapped error", async () => {
    const { c, mf } = retryClient({
      "GET /v1/orgs/studio/spaces": { status: 503, json: { error: "unavailable" } },
    }, 2);
    await expect(c.listFilespaces()).rejects.toMatchObject({ code: ExitCode.GATEWAY_ERROR });
    expect(mf.requests).toHaveLength(3); // initial + 2 retries
  });

  it("does not retry a non-transient 404", async () => {
    const { c, mf } = retryClient({
      "GET /v1/filespaces/active-edit/items/ino-x": { status: 404, json: { error: "no such item" } },
    });
    await expect(c.stat("active-edit", "ino-x")).rejects.toMatchObject({ code: ExitCode.NOT_FOUND });
    expect(mf.requests).toHaveLength(1);
  });
});

describe("HttpGatewayClient — error envelope → stable exit codes (API.md §2)", () => {
  const cases: { status: number; error: string; expect: number }[] = [
    { status: 401, error: "no_token", expect: ExitCode.NOT_AUTHENTICATED },
    { status: 401, error: "expired", expect: ExitCode.TOKEN_EXPIRED },
    { status: 403, error: "forbidden_scope", expect: ExitCode.PERMISSION_DENIED },
    { status: 403, error: "cross_tenant", expect: ExitCode.PERMISSION_DENIED },
    { status: 404, error: "no such item", expect: ExitCode.NOT_FOUND },
    { status: 405, error: "method not allowed", expect: ExitCode.USAGE },
    { status: 409, error: "conflict", expect: ExitCode.CONFLICT },
    { status: 429, error: "rate_limited", expect: ExitCode.GATEWAY_ERROR },
    { status: 400, error: "item required", expect: ExitCode.USAGE },
    { status: 500, error: "boom", expect: ExitCode.GATEWAY_ERROR },
  ];

  for (const tc of cases) {
    it(`${tc.status} ${tc.error} -> exit ${tc.expect}`, async () => {
      // Audit B17/B28: ids are opaque; pass one directly (resolvePathToId passes it through, no walk).
      const { c } = client({
        "GET /v1/filespaces/active-edit/items/ino-ShowA": { status: tc.status, json: { error: tc.error, reason: "x" } },
      });
      await expect(c.stat("active-edit", "ino-ShowA")).rejects.toMatchObject({ code: tc.expect });
    });
  }

  it("a network failure (fetch throws) maps to NETWORK_ERROR", async () => {
    const throwing = new HttpGatewayClient({
      baseUrl: BASE,
      token: TOKEN,
      fetch: async () => {
        throw new Error("ECONNREFUSED");
      },
    });
    await expect(throwing.listFilespaces()).rejects.toMatchObject({ code: ExitCode.NETWORK_ERROR });
  });

  it("409 conflict surfaces conflict detail in the CliError", async () => {
    // Audit B17/B28: ids are opaque; pass one directly so resolvePathToId forwards it
    // without a namespace walk and the 409 surfaces at the grant route under test.
    const { c } = client({
      "POST /v1/filespaces/active-edit/grants": { status: 409, json: { error: "conflict", conflict: true, expected: 3, actual: 5 } },
    });
    await expect(
      c.permissionGrant({ filespace: "active-edit", principal: "x@y", path: "ino-ShowA", level: "read" }),
    ).rejects.toMatchObject({
      code: ExitCode.CONFLICT,
      detail: { conflict: true, expected: 3, actual: 5 },
    });
  });
});

describe("HttpGatewayClient — through the CLI (--json output + exit codes)", () => {
  it("filespace list --json renders the stable success envelope from the wire", async () => {
    const { c } = client({
      "GET /v1/orgs/studio/spaces": { json: { spaces: [{ id: "active-edit", name: "Active Edit", status: "connected", role: "admin" }] } },
    });
    const r = await runCliWith(["--json", "filespace", "list"], c);
    expect(r.code).toBe(0);
    expect(r.json.ok).toBe(true);
    expect(r.json.data[0]).toMatchObject({ id: "active-edit", status: "connected" });
  });

  it("stat on a 403 maps to PERMISSION_DENIED and a JSON error envelope", async () => {
    // Audit B17/B28: ids are opaque; pass one directly so resolvePathToId forwards it
    // without a namespace walk and the 403 surfaces at the stat route under test.
    const { c } = client({
      "GET /v1/filespaces/active-edit/items/ino-Secret": { status: 403, json: { error: "forbidden", reason: "no ACL" } },
    });
    const r = await runCliWith(["--json", "stat", "ino-Secret", "active-edit"], c);
    expect(r.code).toBe(ExitCode.PERMISSION_DENIED);
    expect(r.json.ok).toBe(false);
    expect(r.json.error.code).toBe(ExitCode.PERMISSION_DENIED);
    expect(r.json.error.detail).toMatchObject({ status: 403, gatewayError: "forbidden" });
  });

  it("snapshot list --json comes straight from /v1/filespaces/:fs/snapshots", async () => {
    const { c } = client({
      "GET /v1/filespaces/active-edit/snapshots": { json: [{ id: "snap-1", label: "nightly", scope: "/", createdAt: "2026-06-03T20:00:00Z", immutableUntil: null, scheduleId: "active-fast" }] },
    });
    const r = await runCliWith(["--json", "snapshot", "list", "active-edit"], c);
    expect(r.code).toBe(0);
    expect(r.json.data[0]).toMatchObject({ id: "snap-1", label: "nightly", schedule: "active-fast" });
  });

  it("events --json streams NDJSON synthesized from the change feed", async () => {
    const { c } = client({
      "GET /v1/filespaces/active-edit/changes": { json: { anchor: 2, items: [{ id: "a", parent: "root", name: "a", isDir: false, size: 1, updatedSeq: 2 }], cursor: null } },
    });
    const r = await runCliWith(["--json", "events", "active-edit"], c);
    expect(r.code).toBe(0);
    const lines = r.stdout.filter((l) => l.trim());
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0])).toMatchObject({ type: "modify", path: "/a" });
  });
});
