// SPDX-License-Identifier: AGPL-3.0-or-later
// storage.test.ts — bring-your-own S3-COMPATIBLE storage (storage.ts).
//
// Covers:
//   1. SigV4 presign correctness (KNOWN-ANSWER, frozen clock) for the canonical S3 dialect.
//   2. Multi-backend selection: a per-filespace descriptor (R2 / AWS S3 / Backblaze B2 /
//      MinIO / Wasabi / Ceph) signs against its OWN endpoint/region/bucket; a space with no
//      override inherits the deployment default.
//   3. Credential resolution: default keys vs a credentialRef-named secret pair, fail-closed
//      when a referenced secret is missing.
//   4. Path-style vs virtual-host URL construction (and that path-safe `::` stays literal so
//      the signed-URL format is unchanged from the original single-backend presigner).

import { describe, it, expect, vi, afterEach } from "vitest";
import {
  resolveStorageConfig,
  resolveStorageConfigAsync,
  defaultStorageConfig,
  presignWith,
  presignManyWith,
  objectUrl,
  resolveCredentials,
  credentialEnvSuffix,
  listObjects,
  deleteObjects,
  type StorageConfig,
  type SpaceStorageDescriptor,
} from "../src/storage";
import type { Env } from "../src/env";

// Minimal env stand-in (only the storage fields the resolver reads).
function envWith(over: Record<string, string | undefined> = {}): Env {
  return {
    S3_ENDPOINT: "http://127.0.0.1:9000",
    S3_BUCKET: "cloudfs",
    S3_ACCESS_KEY_ID: "localdev",
    S3_SECRET_ACCESS_KEY: "localdevsecret",
    ...over,
  } as unknown as Env;
}

const FIXED = Date.parse("2026-01-01T00:00:00Z");

afterEach(() => {
  vi.useRealTimers();
});

describe("SigV4 presign — known-answer (frozen clock)", () => {
  it("AWS S3 backend produces the exact expected signature", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(FIXED);
    const cfg: StorageConfig = {
      endpoint: "https://s3.us-east-1.amazonaws.com",
      region: "us-east-1",
      bucket: "mybucket",
      accessKeyId: "AKIDEXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      forcePathStyle: true,
    };
    const url = await presignWith(cfg, "blocks/org1::fs1/ab/obj", "GET", 900);
    expect(url).toBe(
      "https://s3.us-east-1.amazonaws.com/mybucket/blocks/org1::fs1/ab/obj" +
        "?X-Amz-Expires=900&X-Amz-Date=20260101T000000Z&X-Amz-Algorithm=AWS4-HMAC-SHA256" +
        "&X-Amz-Credential=AKIDEXAMPLE%2F20260101%2Fus-east-1%2Fs3%2Faws4_request" +
        "&X-Amz-SignedHeaders=host" +
        "&X-Amz-Signature=852d5dd7c84f73a87a2b6ee5db36f52ffa88416dabc129d1829eb5c57fc6773f",
    );
  });

  it("Cloudflare R2 backend (region=auto, PUT) produces the exact expected signature", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(FIXED);
    const cfg: StorageConfig = {
      endpoint: "https://acct123.r2.cloudflarestorage.com",
      region: "auto",
      bucket: "cloudfs",
      accessKeyId: "R2KEYEXAMPLE",
      secretAccessKey: "r2secretexamplevalue00000000000000000000",
      forcePathStyle: true,
    };
    const url = await presignWith(cfg, "blocks/org1::fs1/ab/obj", "PUT", 300);
    expect(url).toContain("X-Amz-Credential=R2KEYEXAMPLE%2F20260101%2Fauto%2Fs3%2Faws4_request");
    expect(url).toBe(
      "https://acct123.r2.cloudflarestorage.com/cloudfs/blocks/org1::fs1/ab/obj" +
        "?X-Amz-Expires=300&X-Amz-Date=20260101T000000Z&X-Amz-Algorithm=AWS4-HMAC-SHA256" +
        "&X-Amz-Credential=R2KEYEXAMPLE%2F20260101%2Fauto%2Fs3%2Faws4_request" +
        "&X-Amz-SignedHeaders=host%3Bif-none-match" +
        "&X-Amz-Signature=9f0bd612b95b60ac88ea0e3a24f0d08b8510a863bc0e6f476fbe78002a47144f",
    );
  });

  it("Backblaze B2 backend produces the exact expected signature", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(FIXED);
    const cfg: StorageConfig = {
      endpoint: "https://s3.us-west-002.backblazeb2.com",
      region: "us-west-002",
      bucket: "b2bucket",
      accessKeyId: "B2KEYID",
      secretAccessKey: "b2secretkeyexamplevalue000000000000000000",
      forcePathStyle: true,
    };
    const url = await presignWith(cfg, "blocks/org1::fs1/ab/obj", "GET", 600);
    expect(url).toBe(
      "https://s3.us-west-002.backblazeb2.com/b2bucket/blocks/org1::fs1/ab/obj" +
        "?X-Amz-Expires=600&X-Amz-Date=20260101T000000Z&X-Amz-Algorithm=AWS4-HMAC-SHA256" +
        "&X-Amz-Credential=B2KEYID%2F20260101%2Fus-west-002%2Fs3%2Faws4_request" +
        "&X-Amz-SignedHeaders=host" +
        "&X-Amz-Signature=6e32cd074fe4d90d996ab58ccb6e1571ea224f6e940f7d90a231a7741d66f4bb",
    );
  });

  it("the signature is bound to the backend: changing the bucket changes the signature", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(FIXED);
    const base: StorageConfig = {
      endpoint: "https://s3.us-east-1.amazonaws.com",
      region: "us-east-1",
      bucket: "mybucket",
      accessKeyId: "AKIDEXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      forcePathStyle: true,
    };
    const a = await presignWith(base, "blocks/org1::fs1/ab/obj", "GET", 900);
    const b = await presignWith({ ...base, bucket: "otherbucket" }, "blocks/org1::fs1/ab/obj", "GET", 900);
    const sigOf = (u: string) => new URL(u).searchParams.get("X-Amz-Signature");
    expect(sigOf(a)).not.toBe(sigOf(b));
  });

  it("clamps the TTL into [60,900] and rejects illegal methods/keys (defense-in-depth)", async () => {
    const cfg: StorageConfig = {
      endpoint: "https://s3.us-east-1.amazonaws.com",
      region: "us-east-1",
      bucket: "b",
      accessKeyId: "k",
      secretAccessKey: "s",
    };
    const tooLong = await presignWith(cfg, "blocks/x", "GET", 99999);
    expect(new URL(tooLong).searchParams.get("X-Amz-Expires")).toBe("900");
    const tooShort = await presignWith(cfg, "blocks/x", "GET", 1);
    expect(new URL(tooShort).searchParams.get("X-Amz-Expires")).toBe("60");
    await expect(presignWith(cfg, "blocks/x", "DELETE", 300)).rejects.toThrow(/method not allowed/);
    await expect(presignWith(cfg, "../escape", "GET", 300)).rejects.toThrow(/illegal key/);
    await expect(presignWith(cfg, "/abs", "GET", 300)).rejects.toThrow(/illegal key/);
  });
});

describe("URL construction — path-style vs virtual-host", () => {
  it("path-style keeps `::` literal (signed-URL format unchanged from the original presigner)", () => {
    const cfg: StorageConfig = {
      endpoint: "http://127.0.0.1:9000/",
      region: "auto",
      bucket: "cloudfs",
      accessKeyId: "k",
      secretAccessKey: "s",
      forcePathStyle: true,
    };
    expect(objectUrl(cfg, "blocks/org1::fs1/ab/obj")).toBe("http://127.0.0.1:9000/cloudfs/blocks/org1::fs1/ab/obj");
  });

  it("virtual-host hoists the bucket into the hostname", () => {
    const cfg: StorageConfig = {
      endpoint: "https://s3.amazonaws.com",
      region: "us-east-1",
      bucket: "mybucket",
      accessKeyId: "k",
      secretAccessKey: "s",
      forcePathStyle: false,
    };
    expect(objectUrl(cfg, "blocks/k")).toBe("https://mybucket.s3.amazonaws.com/blocks/k");
  });
});

describe("multi-backend selection (resolveStorageConfig)", () => {
  it("a space with NO override inherits the deployment default backend", () => {
    const env = envWith();
    const cfg = resolveStorageConfig(env, null);
    expect(cfg).toEqual(defaultStorageConfig(env));
    expect(cfg.endpoint).toBe("http://127.0.0.1:9000");
    expect(cfg.bucket).toBe("cloudfs");
    expect(cfg.region).toBe("auto");
    expect(cfg.accessKeyId).toBe("localdev");
  });

  it("an empty descriptor (all fields null) also inherits the default", () => {
    const env = envWith();
    const desc: SpaceStorageDescriptor = { provider: "r2", endpoint: null, region: null, bucket: null, credentialRef: null };
    expect(resolveStorageConfig(env, desc)).toEqual(defaultStorageConfig(env));
  });

  it("a per-space AWS S3 backend overrides endpoint/region/bucket and keeps default keys", () => {
    const env = envWith();
    const desc: SpaceStorageDescriptor = {
      provider: "s3",
      endpoint: "https://s3.eu-west-1.amazonaws.com",
      region: "eu-west-1",
      bucket: "team-bucket",
      forcePathStyle: false,
    };
    const cfg = resolveStorageConfig(env, desc);
    expect(cfg.endpoint).toBe("https://s3.eu-west-1.amazonaws.com");
    expect(cfg.region).toBe("eu-west-1");
    expect(cfg.bucket).toBe("team-bucket");
    expect(cfg.forcePathStyle).toBe(false);
    // No credentialRef + own endpoint => its own resolved (default) keys.
    expect(cfg.accessKeyId).toBe("localdev");
  });

  it("the default S3_REGION is honored when set (else 'auto')", () => {
    expect(defaultStorageConfig(envWith({ S3_REGION: "us-east-2" })).region).toBe("us-east-2");
    expect(defaultStorageConfig(envWith()).region).toBe("auto");
  });

  it("R2 stays supported as an S3-compatible backend (its S3 endpoint + region auto)", async () => {
    const env = envWith({
      S3_ACCESS_KEY_ID: "R2KEY",
      S3_SECRET_ACCESS_KEY: "r2secret000000000000000000000000",
    });
    const desc: SpaceStorageDescriptor = {
      provider: "r2",
      endpoint: "https://acct.r2.cloudflarestorage.com",
      region: "auto",
      bucket: "space-bucket",
    };
    const cfg = resolveStorageConfig(env, desc);
    expect(cfg.endpoint).toBe("https://acct.r2.cloudflarestorage.com");
    expect(cfg.region).toBe("auto");
    const url = await presignWith(cfg, "blocks/o::s/x", "GET", 300);
    expect(url).toContain("https://acct.r2.cloudflarestorage.com/space-bucket/blocks/o::s/x");
    expect(url).toContain("%2Fauto%2Fs3%2Faws4_request");
  });
});

describe("credential resolution (secrets never in the registry)", () => {
  it("marks only deployment credentials for optional native verification, even when referenced keys match", async () => {
    const env = envWith({
      S3_ACCESS_KEY_ID__SAME: "localdev",
      S3_SECRET_ACCESS_KEY__SAME: "localdevsecret",
    });
    expect(defaultStorageConfig(env).credentialSource).toBe("deployment-default");
    expect(resolveStorageConfig(env, { bucket: "another" }).credentialSource).toBe("deployment-default");
    expect(resolveStorageConfig(env, { credentialRef: "same" }).credentialSource).toBeUndefined();
    expect((await resolveStorageConfigAsync(env, { credentialRef: "same" }, async () => null)).credentialSource).toBeUndefined();
    const managed = async () => ({ accessKeyId: "localdev", secretAccessKey: "localdevsecret" });
    expect((await resolveStorageConfigAsync(env, { credentialRef: "same" }, managed)).credentialSource).toBeUndefined();
    // Even an over-wide internal resolver result cannot label a referenced
    // credential as deployment-owned by smuggling an extra property.
    expect((await resolveStorageConfigAsync(env, { credentialRef: "same" }, async () => ({
      ...await managed(), credentialSource: "deployment-default" as const,
    }))).credentialSource).toBeUndefined();
  });

  it("preserves an explicit addressing override for exact native-bucket matching", async () => {
    const env = envWith();
    expect(resolveStorageConfig(env, { forcePathStyle: false }).forcePathStyle).toBe(false);
    expect((await resolveStorageConfigAsync(env, { forcePathStyle: false })).forcePathStyle).toBe(false);
  });

  it("keeps temporary session tokens with their exact default or referenced key pair", async () => {
    const env = envWith({
      S3_SESSION_TOKEN: "default-session/+==",
      S3_ACCESS_KEY_ID__TEMP: "temporary-key",
      S3_SECRET_ACCESS_KEY__TEMP: "temporary-secret",
      S3_SESSION_TOKEN__TEMP: "referenced-session/+==",
      S3_ACCESS_KEY_ID__PERMANENT: "permanent-key",
      S3_SECRET_ACCESS_KEY__PERMANENT: "permanent-secret",
    });
    expect(defaultStorageConfig(env).sessionToken).toBe("default-session/+==");
    expect(resolveStorageConfig(env, { bucket: "other" }).sessionToken).toBe("default-session/+==");
    expect(resolveStorageConfig(env, { credentialRef: "temp" }).sessionToken).toBe("referenced-session/+==");
    expect(await resolveStorageConfigAsync(env, { credentialRef: "temp" }, async () => null))
      .toMatchObject({ accessKeyId: "temporary-key", sessionToken: "referenced-session/+==" });
    expect(resolveStorageConfig(env, { credentialRef: "permanent" })).not.toHaveProperty("sessionToken");
    expect(resolveStorageConfig({ ...env, S3_SESSION_TOKEN__PERMANENT: "" }, { credentialRef: "permanent" }))
      .not.toHaveProperty("sessionToken");
    expect(await resolveStorageConfigAsync(env, { credentialRef: "permanent" }, async () => null))
      .not.toHaveProperty("sessionToken");
  });

  it("managed credentials preserve their own session token without borrowing environment tokens", async () => {
    const env = envWith({ S3_SESSION_TOKEN: "default-token", S3_SESSION_TOKEN__MANAGED: "env-token" });
    const descriptor = { credentialRef: "managed" };
    const permanent = { accessKeyId: "managed-key", secretAccessKey: "managed-secret" };
    expect(await resolveStorageConfigAsync(env, descriptor, async () => permanent)).not.toHaveProperty("sessionToken");
    expect(await resolveStorageConfigAsync(env, descriptor, async () => ({ ...permanent, sessionToken: "managed-token" })))
      .toMatchObject({ accessKeyId: "managed-key", sessionToken: "managed-token" });
  });

  it("omits empty session bindings and refuses malformed ones without leaking their value", () => {
    const env = { S3_ACCESS_KEY_ID: "id", S3_SECRET_ACCESS_KEY: "secret" };
    expect(resolveCredentials({ ...env, S3_SESSION_TOKEN: "" })).not.toHaveProperty("sessionToken");
    expect(() => resolveCredentials({ ...env, S3_SESSION_TOKEN: { secret: "private" } }))
      .toThrow("storage: invalid S3 session token");
    expect(() => resolveCredentials({ ...env, S3_SESSION_TOKEN__MISSING: "orphan-token" }, "missing"))
      .toThrow(/missing credentials/);
  });

  it("signs the session token for single and batch URLs, including immutable PUT headers", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(FIXED);
    const config = defaultStorageConfig(envWith({ S3_SESSION_TOKEN: "session/+==" }));
    const key = `blocks/org::space/${"ab".repeat(32)}`;
    const first = new URL(await presignWith(config, key, "GET", 300));
    const changed = new URL(await presignWith({ ...config, sessionToken: "changed" }, key, "GET", 300));
    expect(first.searchParams.get("X-Amz-Security-Token")).toBe("session/+==");
    expect(first.searchParams.get("X-Amz-Signature")).not.toBe(changed.searchParams.get("X-Amz-Signature"));
    const results = await presignManyWith(config, [{ key, method: "GET" }, { key, method: "PUT" }], 300);
    for (const result of results) expect(new URL(result.url!).searchParams.get("X-Amz-Security-Token")).toBe("session/+==");
    expect(new URL(results[1].url!).searchParams.get("X-Amz-SignedHeaders"))
      .toBe("host;if-none-match;x-amz-checksum-sha256");
    expect(results[1].headers?.["if-none-match"]).toBe("*");
  });

  it("includes session credentials on server-side prefix list and delete requests", async () => {
    const config = defaultStorageConfig(envWith({ S3_SESSION_TOKEN: "scoped-session" }));
    const seen: string[] = [];
    const fake = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      expect(headers.get("x-amz-security-token")).toBe("scoped-session");
      expect(headers.get("authorization")).toContain("x-amz-security-token");
      seen.push(init?.method ?? "GET");
      return new Response(init?.method === "POST" ? "<DeleteResult/>" : "<ListBucketResult/>");
    }) as typeof fetch;
    await listObjects(config, "blocks/org::space/", null, fake);
    await deleteObjects(config, "blocks/org::space/", ["blocks/org::space/test"], fake);
    expect(seen).toEqual(["GET", "POST"]);
  });

  it("default credentials come from S3_ACCESS_KEY_ID / S3_SECRET_ACCESS_KEY", () => {
    const c = resolveCredentials({ S3_ACCESS_KEY_ID: "id", S3_SECRET_ACCESS_KEY: "sec" }, null);
    expect(c).toEqual({ accessKeyId: "id", secretAccessKey: "sec" });
  });

  it("a credentialRef selects the S3_ACCESS_KEY_ID__<REF> / S3_SECRET_ACCESS_KEY__<REF> pair", () => {
    const env = {
      S3_ACCESS_KEY_ID: "default",
      S3_SECRET_ACCESS_KEY: "defaultsec",
      S3_ACCESS_KEY_ID__B2: "b2id",
      S3_SECRET_ACCESS_KEY__B2: "b2sec",
    };
    expect(resolveCredentials(env, "b2")).toEqual({ accessKeyId: "b2id", secretAccessKey: "b2sec" });
    // ref normalization: "Backblaze-Prod" -> "BACKBLAZE_PROD"
    expect(credentialEnvSuffix("Backblaze-Prod")).toBe("BACKBLAZE_PROD");
  });

  it("fails closed when a referenced credential pair is missing (never silently uses defaults)", () => {
    const env = { S3_ACCESS_KEY_ID: "default", S3_SECRET_ACCESS_KEY: "defaultsec" };
    expect(() => resolveCredentials(env, "missing")).toThrow(/missing credentials for ref "missing"/);
  });

  it("a per-space backend with a credentialRef signs with the referenced keys", async () => {
    const env = envWith({
      S3_ACCESS_KEY_ID__WASABI: "wasabikey",
      S3_SECRET_ACCESS_KEY__WASABI: "wasabisecret0000000000000000000000",
    } as Record<string, string>);
    const desc: SpaceStorageDescriptor = {
      provider: "wasabi",
      endpoint: "https://s3.us-east-1.wasabisys.com",
      region: "us-east-1",
      bucket: "wbucket",
      credentialRef: "wasabi",
    };
    const cfg = resolveStorageConfig(env, desc);
    expect(cfg.accessKeyId).toBe("wasabikey");
    const url = await presignWith(cfg, "blocks/o::s/x", "GET", 300);
    expect(url).toContain("X-Amz-Credential=wasabikey%2F");
  });

  it("fail-closed propagates through resolveStorageConfig when the ref is unknown", () => {
    const env = envWith();
    const desc: SpaceStorageDescriptor = { provider: "b2", endpoint: "https://x", region: "r", bucket: "b", credentialRef: "nope" };
    expect(() => resolveStorageConfig(env, desc)).toThrow(/missing credentials for ref "nope"/);
  });
});

// ===========================================================================================
// PREFIX-SCOPED SWEEP PRIMITIVES — the data-destroying path. These tests pin the SAFETY
// guarantees: there is NO way to list/delete without a non-empty prefix, the list request always
// carries `prefix=`, and deleteObjects refuses ANY key not under the prefix (fail closed).
// ===========================================================================================
describe("listObjects / deleteObjects — prefix scoping safety", () => {
  const cfg: StorageConfig = {
    endpoint: "https://s3.example.com",
    region: "us-east-1",
    bucket: "bkt",
    accessKeyId: "ak",
    secretAccessKey: "sk000000000000000000000000000000",
    forcePathStyle: true,
  };

  it("listObjects ALWAYS sends prefix= and forwards the continuation token", async () => {
    let seenUrl = "";
    const fake = (async (input: any) => {
      seenUrl = typeof input === "string" ? input : input.url;
      return new Response(
        `<ListBucketResult><Contents><Key>blocks/o::s/a</Key></Contents>` +
        `<IsTruncated>true</IsTruncated><NextContinuationToken>TOK2</NextContinuationToken></ListBucketResult>`,
        { status: 200 },
      );
    }) as unknown as typeof fetch;
    const page = await listObjects(cfg, "blocks/o::s/", "TOK1", fake);
    expect(seenUrl).toContain("prefix=blocks%2Fo%3A%3As%2F");
    expect(seenUrl).toContain("continuation-token=TOK1");
    expect(seenUrl).toContain("list-type=2");
    expect(page.keys).toEqual(["blocks/o::s/a"]);
    expect(page.nextContinuationToken).toBe("TOK2");
  });

  it("listObjects DROPS any server-returned key not under the requested prefix (defense in depth)", async () => {
    const fake = (async () =>
      new Response(
        `<ListBucketResult>` +
        `<Contents><Key>blocks/o::s/keep</Key></Contents>` +
        `<Contents><Key>blocks/o::OTHER/evil</Key></Contents>` +
        `<IsTruncated>false</IsTruncated></ListBucketResult>`,
        { status: 200 },
      )) as unknown as typeof fetch;
    const page = await listObjects(cfg, "blocks/o::s/", null, fake);
    expect(page.keys).toEqual(["blocks/o::s/keep"]); // the out-of-prefix key is filtered out
  });

  it("listObjects REFUSES an empty / whitespace / leading-slash prefix (no whole-bucket list)", async () => {
    const never = (async () => new Response("", { status: 200 })) as unknown as typeof fetch;
    await expect(listObjects(cfg, "", null, never)).rejects.toThrow(/empty prefix/);
    await expect(listObjects(cfg, "   ", null, never)).rejects.toThrow(/empty prefix/);
    await expect(listObjects(cfg, "/blocks/", null, never)).rejects.toThrow(/leading-slash/);
  });

  it("deleteObjects REFUSES the whole batch if ANY key escapes the prefix (fail closed, nothing sent)", async () => {
    let called = false;
    const fake = (async () => {
      called = true;
      return new Response("<DeleteResult/>", { status: 200 });
    }) as unknown as typeof fetch;
    await expect(
      deleteObjects(cfg, "blocks/o::s/", ["blocks/o::s/ok", "blocks/o::OTHER/escape"], fake),
    ).rejects.toThrow(/escapes prefix/);
    expect(called).toBe(false); // NOTHING was put on the wire
  });

  it("deleteObjects REFUSES an empty prefix even with in-looking keys", async () => {
    const never = (async () => new Response("", { status: 200 })) as unknown as typeof fetch;
    await expect(deleteObjects(cfg, "", ["anything"], never)).rejects.toThrow(/empty prefix/);
  });

  it("both REFUSE a path-traversal ('..') prefix (no escape out of the space namespace)", async () => {
    const never = (async () => new Response("", { status: 200 })) as unknown as typeof fetch;
    await expect(listObjects(cfg, "blocks/o::../evil/", null, never)).rejects.toThrow(/illegal prefix/);
    await expect(
      deleteObjects(cfg, "blocks/o::../evil/", ["blocks/o::../evil/k"], never),
    ).rejects.toThrow(/illegal prefix/);
  });

  it("deleteObjects sends a well-formed batch and parses Deleted + Error entries", async () => {
    let body = "";
    const fake = (async (_input: any, init?: any) => {
      body = String(init?.body ?? "");
      return new Response(
        `<DeleteResult>` +
        `<Deleted><Key>blocks/o::s/a</Key></Deleted>` +
        `<Error><Key>blocks/o::s/b</Key><Code>AccessDenied</Code><Message>nope</Message></Error>` +
        `</DeleteResult>`,
        { status: 200 },
      );
    }) as unknown as typeof fetch;
    const res = await deleteObjects(cfg, "blocks/o::s/", ["blocks/o::s/a", "blocks/o::s/b"], fake);
    expect(body).toContain("<Key>blocks/o::s/a</Key>");
    expect(body).toContain("<Key>blocks/o::s/b</Key>");
    expect(res.deleted).toEqual(["blocks/o::s/a"]);
    expect(res.errors).toEqual([{ key: "blocks/o::s/b", code: "AccessDenied", message: "nope" }]);
  });

  it("deleteObjects is a no-op for an empty key list (still requires a valid prefix)", async () => {
    let called = false;
    const fake = (async () => { called = true; return new Response("", { status: 200 }); }) as unknown as typeof fetch;
    const res = await deleteObjects(cfg, "blocks/o::s/", [], fake);
    expect(res).toEqual({ deleted: [], errors: [] });
    expect(called).toBe(false);
  });
});
