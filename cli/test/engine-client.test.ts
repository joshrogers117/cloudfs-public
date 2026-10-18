// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, describe, expect, it } from "vitest";
import { EngineClient } from "../src/engine/client.js";
import { MockGatewayClient } from "../src/gateway/mock.js";
import { ExitCode } from "../src/exit-codes.js";
import { runCliWith } from "./helpers.js";
import { startFakeDaemon, rpcError, type FakeDaemon, type MethodHandler } from "./uds-fake.js";

const daemons: FakeDaemon[] = [];
afterEach(async () => {
  await Promise.all(daemons.splice(0).map((d) => d.close()));
});

/** Start a fake daemon + an EngineClient wired to it (gateway = authed mock). */
async function withDaemon(handlers: Record<string, MethodHandler>) {
  const daemon = await startFakeDaemon(handlers);
  daemons.push(daemon);
  const client = new EngineClient({ socketPath: daemon.socketPath, gateway: new MockGatewayClient({ authenticated: true }) });
  return { daemon, client };
}

const CACHE = {
  filespace: "active-edit",
  location: "/var/cloudfs/cache",
  sizeBytes: 96 * 1024 ** 3,
  usedBytes: 96 * 1024 ** 3,
  pinnedBytes: 4 * 1024 ** 3,
  maxBytes: 256 * 1024 ** 3,
  freeOnVolumeBytes: 500 * 1024 ** 3,
  hitRate: 0.92,
};

describe("EngineClient — request framing & method round-trips (CONTROL-API.md)", () => {
  it("frames a cache.info request as newline JSON-RPC 2.0 and maps the result", async () => {
    const { daemon, client } = await withDaemon({ "cache.info": (ctx) => ({ ...CACHE, filespace: ctx.params.filespace }) });
    const info = await client.cacheInfo("active-edit");
    expect(info).toEqual({
      sizeBytes: CACHE.sizeBytes,
      usedBytes: CACHE.usedBytes,
      pinnedBytes: CACHE.pinnedBytes,
      location: CACHE.location,
      maxBytes: CACHE.maxBytes,
    });
    // request shape: method + params, single recorded call
    expect(daemon.calls).toHaveLength(1);
    expect(daemon.calls[0].method).toBe("cache.info");
    expect(daemon.calls[0].params).toEqual({ filespace: "active-edit" });
  });

  it("cache.setSize sends { filespace, bytes }", async () => {
    const { daemon, client } = await withDaemon({ "cache.setSize": (ctx) => ({ ...CACHE, maxBytes: ctx.params.bytes }) });
    const info = await client.cacheSetSize("active-edit", 512 * 1024 ** 3);
    expect(info.maxBytes).toBe(512 * 1024 ** 3);
    expect(daemon.calls[0].params).toEqual({ filespace: "active-edit", bytes: 512 * 1024 ** 3 });
  });

  it("cache.setLocation sends { filespace, path }", async () => {
    const { daemon, client } = await withDaemon({ "cache.setLocation": (ctx) => ({ ...CACHE, location: ctx.params.path }) });
    const info = await client.cacheSetLocation("active-edit", "/mnt/fast/cache");
    expect(info.location).toBe("/mnt/fast/cache");
    expect(daemon.calls[0].params).toEqual({ filespace: "active-edit", path: "/mnt/fast/cache" });
  });

  it("pin / unpin / prefetch round-trip with recursive + queuedBlocks", async () => {
    const { daemon, client } = await withDaemon({
      pin: (ctx) => ({ path: ctx.params.path, pinned: true, recursive: ctx.params.recursive, blocks: 12 }),
      unpin: (ctx) => ({ path: ctx.params.path, pinned: false, recursive: ctx.params.recursive, blocks: 0 }),
      prefetch: (ctx) => ({ path: ctx.params.path, queuedBlocks: 128 }),
    });
    expect(await client.pin("active-edit", "/ShowA", true)).toEqual({ path: "/ShowA", pinned: true });
    expect(await client.unpin("active-edit", "/ShowA", false)).toEqual({ path: "/ShowA", pinned: false });
    expect(await client.prefetch("active-edit", "/ShowA")).toEqual({ path: "/ShowA", queuedBlocks: 128 });
    expect(daemon.calls.map((c) => c.method)).toEqual(["pin", "unpin", "prefetch"]);
    expect(daemon.calls[0].params).toEqual({ filespace: "active-edit", path: "/ShowA", recursive: true });
  });

  it("pin.list maps per-item byte accounting + cache state (CONTROL-API.md §5.4)", async () => {
    const { daemon, client } = await withDaemon({
      "pin.list": () => [
        { path: "projectA/timeline.prproj", pinned: true, recursive: false, blocks: 128, cachedBytes: 67108864, totalBytes: 134217728, cacheState: "pinning" },
        { path: "projectB/", pinned: true, recursive: true, blocks: 4, cachedBytes: 4194304, totalBytes: 4194304, cacheState: "pinned" },
      ],
    });
    const pins = await client.pinList("active-edit");
    expect(pins).toEqual([
      { path: "projectA/timeline.prproj", recursive: false, cachedBytes: 67108864, totalBytes: 134217728, blocks: 128, state: "pinning" },
      { path: "projectB/", recursive: true, cachedBytes: 4194304, totalBytes: 4194304, blocks: 4, state: "pinned" },
    ]);
    expect(daemon.calls[0].method).toBe("pin.list");
    expect(daemon.calls[0].params).toEqual({ filespace: "active-edit" });
  });

  it("pin.list tolerates an older daemon that omits the appended byte fields", async () => {
    const { client } = await withDaemon({
      // Older engine: only the original PinState fields present.
      "pin.list": () => [{ path: "legacy/clip.mov", pinned: true, recursive: false, blocks: 9 }],
    });
    const pins = await client.pinList("active-edit");
    // Missing bytes → 0; missing state → derived (not yet known-resident →
    // "pinning"; the engine reports two states only) (CONTRACTS.md §4.3).
    expect(pins).toEqual([
      { path: "legacy/clip.mov", recursive: false, cachedBytes: 0, totalBytes: 0, blocks: 9, state: "pinning" },
    ]);
  });

  it("mount / unmount map EngineFilespace → Filespace", async () => {
    const { daemon, client } = await withDaemon({
      mount: (ctx) => ({ id: ctx.params.filespace, name: "Active Edit", status: "connected", mountPath: ctx.params.at ?? "/Volumes/active-edit", rootPoint: null, role: "admin" }),
      unmount: (ctx) => ({ id: ctx.params.filespace, name: "Active Edit", status: "connected", mountPath: null, rootPoint: null, role: "admin" }),
    });
    const m = await client.mount({ filespace: "active-edit", at: "/Volumes/ae" });
    expect(m).toMatchObject({ id: "active-edit", status: "connected", mountPath: "/Volumes/ae" });
    const u = await client.unmount("active-edit");
    expect(u.mountPath).toBeNull();
    expect(daemon.calls[0].params).toMatchObject({ filespace: "active-edit", at: "/Volumes/ae" });
  });

  it("flush + sync.state round-trip (the `wait` poll backing)", async () => {
    const { client } = await withDaemon({
      flush: (ctx) => ({ path: ctx.params.path, inSync: false, pendingUploads: 2, pendingBytes: 8 }),
      "sync.state": (ctx) => ({ path: ctx.params.path, inSync: true, pendingUploads: 0, pendingBytes: 0 }),
    });
    expect(await client.flush("active-edit", "/ShowA")).toMatchObject({ inSync: false, pendingUploads: 2 });
    expect(await client.syncState("active-edit", "/ShowA")).toMatchObject({ inSync: true, pendingUploads: 0 });
  });
});

describe("EngineClient — event stream → NDJSON", () => {
  it("subscribes once and yields activity notifications as ChangeEvents", async () => {
    const { daemon, client } = await withDaemon({
      "events.subscribe": (ctx) => {
        // Emit three activity notifications then close (server-driven stream).
        const evs = [
          { seq: 1, type: "upload", path: "/ShowA/a.mov", actor: "ci@svc", ts: "2026-06-04T00:00:00Z" },
          { seq: 2, type: "modify", path: "/ShowA/b.mov", actor: "ci@svc", ts: "2026-06-04T00:00:01Z" },
          { seq: 3, type: "create", path: "/Other/c.mov", actor: "ci@svc", ts: "2026-06-04T00:00:02Z" },
        ];
        for (const event of evs) ctx.notify("activity", { filespace: "active-edit", event });
        return { subscribed: true };
      },
    });
    const seen: any[] = [];
    for await (const e of client.events({ filespace: "active-edit" })) {
      seen.push(e);
      if (seen.length === 3) break;
    }
    client.close();
    expect(seen.map((e) => e.type)).toEqual(["upload", "modify", "create"]);
    expect(daemon.calls[0].method).toBe("events.subscribe");
    expect(daemon.calls[0].params).toMatchObject({ filespace: "active-edit", kinds: ["activity"] });
  });

  it("activity() collects up to the limit and filters by path via events()", async () => {
    const { client } = await withDaemon({
      "events.subscribe": (ctx) => {
        ctx.notify("activity", { filespace: "active-edit", event: { seq: 1, type: "upload", path: "/ShowA/a", actor: "x", ts: "t" } });
        ctx.notify("activity", { filespace: "active-edit", event: { seq: 2, type: "modify", path: "/ShowA/b", actor: "x", ts: "t" } });
        return { subscribed: true };
      },
    });
    const acts = await client.activity({ filespace: "active-edit", limit: 1 });
    expect(acts).toHaveLength(1);
    client.close();
  });
});

describe("EngineClient — JSON-RPC error code → stable exit code (CONTROL-API.md §2)", () => {
  const cases: { code: number; expect: number }[] = [
    { code: -32602, expect: ExitCode.USAGE },
    { code: -32010, expect: ExitCode.NOT_CONNECTED },
    { code: -32020, expect: ExitCode.NOT_FOUND },
    { code: -32021, expect: ExitCode.CONFLICT },
    { code: -32022, expect: ExitCode.LOCKED },
    { code: -32030, expect: ExitCode.PERMISSION_DENIED },
    { code: -32040, expect: ExitCode.GATEWAY_ERROR },
    { code: -32041, expect: ExitCode.NETWORK_ERROR },
    { code: -32050, expect: ExitCode.SYNC_TIMEOUT },
    { code: -32051, expect: ExitCode.SYNC_FAILED },
    { code: -32603, expect: ExitCode.GENERIC },
  ];
  for (const tc of cases) {
    it(`engine code ${tc.code} -> exit ${tc.expect}`, async () => {
      const { client } = await withDaemon({ "cache.info": () => { throw rpcError(tc.code, "boom", { x: 1 }); } });
      await expect(client.cacheInfo("active-edit")).rejects.toMatchObject({ code: tc.expect });
    });
  }

  it("a sync_timeout carries its data (pendingUploads) in the CliError detail", async () => {
    const { client } = await withDaemon({
      flush: () => { throw rpcError(-32050, "deadline", { pendingUploads: 3, pendingBytes: 99 }); },
    });
    await expect(client.flush("active-edit", "/ShowA")).rejects.toMatchObject({
      code: ExitCode.SYNC_TIMEOUT,
      detail: { engineCode: -32050, pendingUploads: 3, pendingBytes: 99 },
    });
  });

  it("a missing socket surfaces ENGINE_UNAVAILABLE (exit 42) — a transport condition", async () => {
    const client = new EngineClient({ socketPath: "/tmp/definitely-not-a-real-cloudfsd.sock", gateway: new MockGatewayClient({ authenticated: true }) });
    await expect(client.cacheInfo("active-edit")).rejects.toMatchObject({ code: ExitCode.ENGINE_UNAVAILABLE });
  });
});

describe("EngineClient — through the CLI (local commands hit the daemon)", () => {
  it("`cache info --json` renders the engine result via the stable envelope", async () => {
    const { client } = await withDaemon({ "cache.info": () => CACHE });
    const r = await runCliWith(["--json", "cache", "info", "active-edit"], client);
    expect(r.code).toBe(0);
    expect(r.json.ok).toBe(true);
    expect(r.json.data).toMatchObject({ location: CACHE.location, maxBytes: CACHE.maxBytes });
    client.close();
  });

  it("`wait` polls sync.state through the daemon and exits 0 when in sync", async () => {
    const { client } = await withDaemon({ "sync.state": (ctx) => ({ path: ctx.params.path, inSync: true, pendingUploads: 0, pendingBytes: 0 }) });
    const r = await runCliWith(["--json", "wait", "/ShowA", "active-edit"], client);
    expect(r.code).toBe(0);
    expect(r.json.data).toMatchObject({ inSync: true });
    client.close();
  });

  it("`pin` failure maps the engine code to the CLI exit code + JSON error envelope", async () => {
    const { client } = await withDaemon({ pin: () => { throw rpcError(-32020, "no such path"); } });
    const r = await runCliWith(["--json", "cache", "pin", "/ghost", "active-edit"], client);
    expect(r.code).toBe(ExitCode.NOT_FOUND);
    expect(r.json.ok).toBe(false);
    expect(r.json.error.code).toBe(ExitCode.NOT_FOUND);
    client.close();
  });

  it("`events --json` streams NDJSON from the daemon notifications", async () => {
    const { client } = await withDaemon({
      "events.subscribe": (ctx) => {
        ctx.notify("activity", { filespace: "active-edit", event: { seq: 1, type: "upload", path: "/a", actor: "x", ts: "t" } });
        return { subscribed: true };
      },
    });
    // events() runs until the connection closes; close the client shortly after.
    const p = runCliWith(["--json", "events", "active-edit"], client);
    setTimeout(() => client.close(), 50);
    const r = await p;
    const lines = r.stdout.filter((l) => l.trim());
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0])).toMatchObject({ type: "upload", path: "/a" });
  });
});
