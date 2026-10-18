// SPDX-License-Identifier: AGPL-3.0-or-later
// storage-credentials.test.ts — UI-managed (encrypted-at-rest) object-storage credentials +
// the storage connection-test probe (storage-credentials.ts + security/storage-crypto.ts).
//
// Covers:
//   1. AES-256-GCM round-trip: seal → open recovers the secret; fail-closed when STORAGE_ENC_KEY
//      is unset/malformed; the GCM tag rejects tampering; the secret never appears in plaintext.
//   2. Credential CRUD via the handler over an in-memory OrgStub: create (201, no secret echoed),
//      list (never includes the secret), delete (204), delete-in-use → 409 + referencing spaces.
//   3. Role gating: a non-admin caller is 403 on every route.
//   4. The connection-test probe against a KNOWN-ANSWER mocked S3 fetch (PUT/GET/DELETE/LIST) —
//      structured result, non-empty-prefix sampleKeys, and graceful failure mapping (no throw).
//   5. Presign resolution managed-FIRST: a credentialRef that matches a managed id decrypts +
//      signs with the managed keys, NOT the env S3_*__<REF> fallback.

import { describe, it, expect } from "vitest";
import {
  sealSecret,
  openSecret,
  importStorageKey,
} from "../src/security/storage-crypto";
import {
  handleStorageCredentialsRequest,
  probeStorage,
  managedCredentialResolver,
  storageEndpointSsrfReason,
  type OrgStub,
  type StorageCredential,
  type ProbeDeps,
} from "../src/storage-credentials";
import { resolveStorageConfigAsync, presignWith, type StorageConfig } from "../src/storage";
import type { AuthedContext } from "../src/org-do";
import type { Env } from "../src/env";

const ENC_KEY = "qbQu5yxLGHtdYKJ6z84mem+Mn5vo5PdUJvawJ0T6D8E="; // 32 bytes base64 (test-only)

function envWith(over: Record<string, string | undefined> = {}): Env {
  return {
    S3_ENDPOINT: "http://127.0.0.1:9000",
    S3_BUCKET: "cloudfs",
    S3_ACCESS_KEY_ID: "localdev",
    S3_SECRET_ACCESS_KEY: "localdevsecret",
    STORAGE_ENC_KEY: ENC_KEY,
    ...over,
  } as unknown as Env;
}

// ---- in-memory OrgStub (the slice storage-credentials.ts needs) ------------------------
interface StoredRow {
  id: string;
  orgId: string;
  label: string;
  accessKeyId: string;
  secretIv: string;
  secretCiphertext: string;
  createdAt: number;
}
function makeOrgStub(opts: { spacesUsing?: Record<string, string[]> } = {}): OrgStub & { _rows: Map<string, StoredRow> } {
  const rows = new Map<string, StoredRow>();
  const spacesUsing = opts.spacesUsing ?? {};
  return {
    _rows: rows,
    async listStorageCredentials(): Promise<StorageCredential[]> {
      return [...rows.values()].map((r) => ({ id: r.id, label: r.label, accessKeyId: r.accessKeyId, createdAt: r.createdAt }));
    },
    async putStorageCredential(input) {
      const id = `scr-${crypto.randomUUID()}`;
      const row: StoredRow = { id, orgId: input.orgId, label: input.label, accessKeyId: input.accessKeyId, secretIv: input.secretIv, secretCiphertext: input.secretCiphertext, createdAt: Date.now() };
      rows.set(id, row);
      return { id, label: row.label, accessKeyId: row.accessKeyId, createdAt: row.createdAt };
    },
    async getStorageCredential(id) {
      const r = rows.get(id);
      return r ? { id: r.id, accessKeyId: r.accessKeyId, secretIv: r.secretIv, secretCiphertext: r.secretCiphertext } : null;
    },
    async spacesUsingStorageCredential(id) {
      return spacesUsing[id] ?? [];
    },
    async deleteStorageCredential(id) {
      return rows.delete(id);
    },
  };
}

const ADMIN: AuthedContext = { principalUserId: "usr-admin", orgRole: "admin" };
const OWNER: AuthedContext = { principalUserId: "usr-owner", orgRole: "owner" };
const STANDARD: AuthedContext = { principalUserId: "usr-std", orgRole: "standard" };

function req(method: string, body?: unknown): Request {
  return new Request("https://gw.local/v1/orgs/org1/storage-credentials", {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

describe("storage-crypto — AES-256-GCM envelope", () => {
  it("opens the same envelope with equivalent hex and base64 deployment keys", async () => {
    const hex = Array.from(atob(ENC_KEY), c => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
    const sealed = await sealSecret(hex.toUpperCase(), "hex-key deployment");
    expect(await openSecret(ENC_KEY, sealed)).toBe("hex-key deployment");
    expect(await openSecret(hex, await sealSecret(ENC_KEY, "base64-key deployment"))).toBe("base64-key deployment");
  });
  it("seals then opens, recovering the exact secret", async () => {
    const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const sealed = await sealSecret(ENC_KEY, secret);
    expect(sealed.iv).toBeTruthy();
    expect(sealed.ciphertext).toBeTruthy();
    // ciphertext must NOT contain the plaintext secret (it's encrypted).
    expect(atob(sealed.ciphertext)).not.toContain("EXAMPLEKEY");
    const back = await openSecret(ENC_KEY, sealed);
    expect(back).toBe(secret);
  });

  it("uses a fresh IV per call (no nonce reuse) — same plaintext seals differently", async () => {
    const a = await sealSecret(ENC_KEY, "samesecret");
    const b = await sealSecret(ENC_KEY, "samesecret");
    expect(a.iv).not.toBe(b.iv);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });

  it("the GCM tag rejects tampered ciphertext", async () => {
    const sealed = await sealSecret(ENC_KEY, "secret-value");
    const bytes = Uint8Array.from(atob(sealed.ciphertext), (c) => c.charCodeAt(0));
    bytes[0] ^= 0xff; // flip a bit
    const tampered = { iv: sealed.iv, ciphertext: btoa(String.fromCharCode(...bytes)) };
    await expect(openSecret(ENC_KEY, tampered)).rejects.toThrow();
  });

  it("a different key cannot decrypt (cross-key isolation)", async () => {
    const other = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; // 32 bytes of zero
    const sealed = await sealSecret(ENC_KEY, "secret-value");
    await expect(openSecret(other, sealed)).rejects.toThrow();
  });

  it("fails closed when STORAGE_ENC_KEY is unset or wrong-length", async () => {
    await expect(importStorageKey(undefined)).rejects.toThrow(/not configured/);
    await expect(importStorageKey("")).rejects.toThrow(/not configured/);
    await expect(importStorageKey("dG9vc2hvcnQ=")).rejects.toThrow(/32 bytes/); // "tooshort" -> 8 bytes
    await expect(sealSecret(undefined, "x")).rejects.toThrow(/not configured/);
  });
});

describe("credential CRUD handler (owner/admin gated; secret never leaks)", () => {
  it("POST creates a credential and returns the SAFE shape (no secret)", async () => {
    const org = makeOrgStub();
    const res = await handleStorageCredentialsRequest(
      req("POST", { label: "Backblaze prod", accessKeyId: "AKID123", secretAccessKey: "supersecretvalue" }),
      envWith(), ADMIN, ["storage-credentials"], "org1", { org },
    );
    expect(res?.status).toBe(201);
    const body = (await res!.json()) as Record<string, unknown>;
    expect(body.id).toMatch(/^scr-/);
    expect(body.label).toBe("Backblaze prod");
    expect(body.accessKeyId).toBe("AKID123");
    expect(body.createdAt).toBeTypeOf("number");
    // the secret must NOT be echoed in any form
    expect(JSON.stringify(body)).not.toContain("supersecretvalue");
    expect(body).not.toHaveProperty("secretAccessKey");
    // the stored row keeps the secret ENCRYPTED, never plaintext
    const stored = [...org._rows.values()][0];
    expect(JSON.stringify(stored)).not.toContain("supersecretvalue");
    expect(await openSecret(ENC_KEY, { iv: stored.secretIv, ciphertext: stored.secretCiphertext })).toBe("supersecretvalue");
  });

  it("GET lists credentials WITHOUT the secret", async () => {
    const org = makeOrgStub();
    await handleStorageCredentialsRequest(req("POST", { label: "L1", accessKeyId: "AK1", secretAccessKey: "secret-one" }), envWith(), ADMIN, ["storage-credentials"], "org1", { org });
    const res = await handleStorageCredentialsRequest(
      new Request("https://gw.local/v1/orgs/org1/storage-credentials", { method: "GET" }),
      envWith(), OWNER, ["storage-credentials"], "org1", { org },
    );
    expect(res?.status).toBe(200);
    const body = (await res!.json()) as { credentials: StorageCredential[] };
    expect(body.credentials).toHaveLength(1);
    expect(body.credentials[0].label).toBe("L1");
    expect(JSON.stringify(body)).not.toContain("secret-one");
    expect(body.credentials[0]).not.toHaveProperty("secretAccessKey");
  });

  it("POST validates required fields (400 on missing secret)", async () => {
    const org = makeOrgStub();
    const res = await handleStorageCredentialsRequest(
      req("POST", { label: "L", accessKeyId: "AK" }),
      envWith(), ADMIN, ["storage-credentials"], "org1", { org },
    );
    expect(res?.status).toBe(400);
  });

  it("POST fails closed (500 storage_enc_key_unconfigured) when STORAGE_ENC_KEY is unset", async () => {
    const org = makeOrgStub();
    const res = await handleStorageCredentialsRequest(
      req("POST", { label: "L", accessKeyId: "AK", secretAccessKey: "s" }),
      envWith({ STORAGE_ENC_KEY: undefined }), ADMIN, ["storage-credentials"], "org1", { org },
    );
    expect(res?.status).toBe(500);
    expect((await res!.json() as any).error).toBe("storage_enc_key_unconfigured");
    expect(org._rows.size).toBe(0); // nothing persisted
  });

  it("DELETE removes an unused credential (204)", async () => {
    const org = makeOrgStub();
    const created = (await (await handleStorageCredentialsRequest(req("POST", { label: "L", accessKeyId: "AK", secretAccessKey: "s" }), envWith(), ADMIN, ["storage-credentials"], "org1", { org }))!.json()) as { id: string };
    const res = await handleStorageCredentialsRequest(
      new Request(`https://gw.local/v1/orgs/org1/storage-credentials/${created.id}`, { method: "DELETE" }),
      envWith(), ADMIN, ["storage-credentials", created.id], "org1", { org },
    );
    expect(res?.status).toBe(204);
    expect(org._rows.size).toBe(0);
  });

  it("DELETE of an in-use credential → 409 credential_in_use with referencing space names", async () => {
    const org = makeOrgStub();
    const created = (await (await handleStorageCredentialsRequest(req("POST", { label: "L", accessKeyId: "AK", secretAccessKey: "s" }), envWith(), ADMIN, ["storage-credentials"], "org1", { org }))!.json()) as { id: string };
    // make a filespace reference it
    (org.spacesUsingStorageCredential as any) = async (id: string) => (id === created.id ? ["Active Edit", "Archive"] : []);
    const res = await handleStorageCredentialsRequest(
      new Request(`https://gw.local/v1/orgs/org1/storage-credentials/${created.id}`, { method: "DELETE" }),
      envWith(), ADMIN, ["storage-credentials", created.id], "org1", { org },
    );
    expect(res?.status).toBe(409);
    const body = (await res!.json()) as any;
    expect(body.error).toBe("credential_in_use");
    expect(body.spaces).toEqual(["Active Edit", "Archive"]);
    expect(org._rows.size).toBe(1); // NOT deleted
  });

  it("DELETE of an unknown id → 404", async () => {
    const org = makeOrgStub();
    const res = await handleStorageCredentialsRequest(
      new Request("https://gw.local/v1/orgs/org1/storage-credentials/scr-nope", { method: "DELETE" }),
      envWith(), ADMIN, ["storage-credentials", "scr-nope"], "org1", { org },
    );
    expect(res?.status).toBe(404);
  });

  it("rejects a non-admin caller on every route (403)", async () => {
    const org = makeOrgStub();
    const list = await handleStorageCredentialsRequest(new Request("https://gw.local/v1/orgs/org1/storage-credentials", { method: "GET" }), envWith(), STANDARD, ["storage-credentials"], "org1", { org });
    expect(list?.status).toBe(403);
    const create = await handleStorageCredentialsRequest(req("POST", { label: "L", accessKeyId: "AK", secretAccessKey: "s" }), envWith(), STANDARD, ["storage-credentials"], "org1", { org });
    expect(create?.status).toBe(403);
  });

  it("returns null for a non-matching path (lets the gateway 404)", async () => {
    const org = makeOrgStub();
    const res = await handleStorageCredentialsRequest(new Request("https://gw.local/x", { method: "GET" }), envWith(), ADMIN, ["something-else"], "org1", { org });
    expect(res).toBeNull();
  });
});

// ---- known-answer S3 mock fetch for the probe -----------------------------------------
// A tiny in-memory bucket keyed by the path; supports PUT/GET/DELETE on objects and a
// ListObjectsV2 GET (list-type=2). Returns S3-shaped XML for listing.
function makeS3Mock(initial: Record<string, string> = {}): ProbeDeps & { _store: Map<string, string>; _calls: string[] } {
  const store = new Map(Object.entries(initial));
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url);
    const method = (init?.method ?? "GET").toUpperCase();
    calls.push(`${method} ${url.pathname}`);
    // ListObjectsV2 ?list-type=2 — path is /<bucket> (path-style)
    if (method === "GET" && url.searchParams.get("list-type") === "2") {
      const prefix = url.searchParams.get("prefix") ?? "";
      // the bucket is the first path segment; keys are stored WITHOUT the bucket
      const keys = [...store.keys()].filter((k) => k.startsWith(prefix));
      const contents = keys.map((k) => `<Contents><Key>${k}</Key></Contents>`).join("");
      const xml = `<?xml version="1.0"?><ListBucketResult>${contents}</ListBucketResult>`;
      return new Response(xml, { status: 200, headers: { "content-type": "application/xml" } });
    }
    // object ops — derive the key as the path after /<bucket>/
    const parts = url.pathname.split("/").filter(Boolean);
    const key = parts.slice(1).join("/"); // drop the bucket segment
    if (method === "PUT") {
      const body = init?.body ? String(init.body) : "";
      store.set(key, body);
      return new Response(null, { status: 200 });
    }
    if (method === "GET") {
      if (!store.has(key)) return new Response("not found", { status: 404 });
      return new Response(store.get(key)!, { status: 200 });
    }
    if (method === "DELETE") {
      store.delete(key);
      return new Response(null, { status: 204 });
    }
    return new Response("bad", { status: 400 });
  }) as typeof fetch;
  return { fetch: fetchImpl, _store: store, _calls: calls };
}

const PROBE_CFG: StorageConfig = {
  endpoint: "https://s3.us-east-1.amazonaws.com",
  region: "us-east-1",
  bucket: "mybucket",
  accessKeyId: "AKIDEXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  forcePathStyle: true,
};

describe("connection-test probe (known-answer S3 mock)", () => {
  it("authenticates every probe operation with the temporary session token", async () => {
    const mock = makeS3Mock();
    const methods: string[] = [];
    const result = await probeStorage({ ...PROBE_CFG, sessionToken: "session/+==" }, "blocks/org1::fs1", {
      fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
        const method = (init?.method ?? "GET").toUpperCase();
        const headers = new Headers(init?.headers);
        if (url.searchParams.get("list-type") === "2" || method === "DELETE") {
          // Server-side LIST/DELETE are header-signed: R2 rejects a query-string token on
          // ListObjectsV2 with 501 NotImplemented (observed live with temporary credentials).
          expect(headers.get("x-amz-security-token")).toBe("session/+==");
          expect(headers.get("authorization")).toMatch(/^AWS4-HMAC-SHA256 /);
          expect(url.searchParams.has("X-Amz-Security-Token")).toBe(false);
          expect(url.searchParams.has("X-Amz-Signature")).toBe(false);
        } else {
          // Object PUT/GET keep the presigned form clients receive; R2 accepts the token there.
          expect(url.searchParams.get("X-Amz-Security-Token")).toBe("session/+==");
        }
        methods.push(method);
        return mock.fetch(input, init);
      }) as typeof fetch,
    });
    expect(result).toMatchObject({ reachable: true, canWrite: true, canRead: true, canDelete: true });
    expect(methods).toEqual(["GET", "PUT", "GET", "DELETE"]);
  });

  it("PUT→GET→DELETE round-trips and reports an EMPTY prefix", async () => {
    const mock = makeS3Mock();
    const result = await probeStorage(PROBE_CFG, "blocks/org1::fs1", mock);
    expect(result.reachable).toBe(true);
    expect(result.canWrite).toBe(true);
    expect(result.canRead).toBe(true);
    expect(result.canDelete).toBe(true);
    expect(result.prefixEmpty).toBe(true);
    expect(result.error).toBeUndefined();
    // the throwaway object was cleaned up (DELETE ran)
    expect([...mock._store.keys()]).toHaveLength(0);
    // probe order: LIST then PUT, GET, DELETE
    expect(mock._calls.some((c) => c.startsWith("PUT"))).toBe(true);
    expect(mock._calls.some((c) => c.startsWith("DELETE"))).toBe(true);
  });

  it("reports a NON-empty prefix + sampleKeys (powers the bucket-not-empty warning)", async () => {
    const mock = makeS3Mock({
      "blocks/org1::fs1/a.mov": "x",
      "blocks/org1::fs1/b.mov": "y",
    });
    const result = await probeStorage(PROBE_CFG, "blocks/org1::fs1", mock);
    expect(result.reachable).toBe(true);
    expect(result.prefixEmpty).toBe(false);
    expect(result.sampleKeys).toEqual(["blocks/org1::fs1/a.mov", "blocks/org1::fs1/b.mov"]);
    // the conntest object itself is excluded from the sample
    expect(result.sampleKeys!.every((k) => !k.includes("conntest"))).toBe(true);
  });

  it("maps an unreachable/denied LIST into reachable:false + error (never throws)", async () => {
    const denied: ProbeDeps = { fetch: (async () => new Response("denied", { status: 403 })) as typeof fetch };
    const result = await probeStorage(PROBE_CFG, "blocks/x", denied);
    expect(result.reachable).toBe(false);
    expect(result.canWrite).toBe(false);
    expect(result.error).toBe("list_failed_403");
  });

  it("reachable but write-denied → canWrite:false with a mapped error (no throw)", async () => {
    const mock = makeS3Mock();
    const partial: ProbeDeps = {
      fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
        const method = (init?.method ?? "GET").toUpperCase();
        if (method === "PUT") return new Response("no", { status: 403 });
        return mock.fetch(input, init);
      }) as typeof fetch,
    };
    const result = await probeStorage(PROBE_CFG, "blocks/x", partial);
    expect(result.reachable).toBe(true);
    expect(result.canWrite).toBe(false);
    expect(result.canRead).toBe(false); // skipped because write failed
    expect(result.error).toBe("put_failed_403");
  });
});

describe("presign resolution — MANAGED credential resolved FIRST", () => {
  it("a credentialRef matching a managed id decrypts + signs with the MANAGED keys (not env)", async () => {
    const org = makeOrgStub();
    // save a managed credential, capture its id
    const created = (await (await handleStorageCredentialsRequest(
      req("POST", { label: "Wasabi", accessKeyId: "MANAGEDKEY", secretAccessKey: "managed-secret-value-000000000000" }),
      envWith(), ADMIN, ["storage-credentials"], "org1", { org },
    ))!.json()) as { id: string };

    const env = envWith({
      // an env fallback EXISTS for a different-cased suffix — must be IGNORED in favor of managed.
      S3_SESSION_TOKEN: "unrelated-default-session",
      [`S3_ACCESS_KEY_ID__${created.id.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}`]: "ENVKEY",
      [`S3_SECRET_ACCESS_KEY__${created.id.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}`]: "envsecret",
      [`S3_SESSION_TOKEN__${created.id.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}`]: "unrelated-ref-session",
    } as Record<string, string>);

    const managed = managedCredentialResolver(env, org);
    const cfg = await resolveStorageConfigAsync(
      env,
      { provider: "wasabi", endpoint: "https://s3.us-east-1.wasabisys.com", region: "us-east-1", bucket: "wb", credentialRef: created.id },
      managed,
    );
    expect(cfg.accessKeyId).toBe("MANAGEDKEY");
    const url = await presignWith(cfg, "blocks/o::s/x", "GET", 300);
    expect(url).toContain("X-Amz-Credential=MANAGEDKEY%2F");
    expect(url).not.toContain("ENVKEY");
    expect(new URL(url).searchParams.has("X-Amz-Security-Token")).toBe(false);
  });

  it("falls back to the env S3_*__<REF> scheme when the ref is NOT a managed id", async () => {
    const org = makeOrgStub();
    const env = envWith({ S3_ACCESS_KEY_ID__B2: "B2KEY", S3_SECRET_ACCESS_KEY__B2: "b2secret" } as Record<string, string>);
    const managed = managedCredentialResolver(env, org);
    const cfg = await resolveStorageConfigAsync(
      env,
      { provider: "b2", endpoint: "https://s3.us-west-002.backblazeb2.com", region: "us-west-002", bucket: "b2b", credentialRef: "b2" },
      managed,
    );
    expect(cfg.accessKeyId).toBe("B2KEY");
  });

  it("fails closed when a managed-first ref resolves to NEITHER managed nor env", async () => {
    const org = makeOrgStub();
    const env = envWith();
    const managed = managedCredentialResolver(env, org);
    await expect(
      resolveStorageConfigAsync(env, { endpoint: "https://x", region: "r", bucket: "b", credentialRef: "ghost" }, managed),
    ).rejects.toThrow(/missing credentials for ref "ghost"/);
  });
});

// Audit B16 (SSRF) — the connection-test probe fetches an ADMIN-SUPPLIED endpoint. The guard
// rejects internal targets so the worker can't be used as a proxy to internal services.
describe("B16: storage endpoint SSRF guard", () => {
  it("allows a public https S3 endpoint", () => {
    expect(storageEndpointSsrfReason("https://s3.us-east-1.amazonaws.com")).toBeNull();
    expect(storageEndpointSsrfReason("https://acct.r2.cloudflarestorage.com")).toBeNull();
  });
  it("ALWAYS blocks cloud-metadata (even with allowPrivate)", () => {
    expect(storageEndpointSsrfReason("http://169.254.169.254/latest/meta-data/")).toBe("endpoint_targets_cloud_metadata");
    expect(storageEndpointSsrfReason("http://169.254.169.254/", true)).toBe("endpoint_targets_cloud_metadata");
  });
  it("blocks loopback / private / link-local hosts by default", () => {
    expect(storageEndpointSsrfReason("http://localhost:9000")).toBe("endpoint_targets_a_local_host");
    expect(storageEndpointSsrfReason("http://127.0.0.1:9000")).toBe("endpoint_targets_a_private_ip");
    expect(storageEndpointSsrfReason("http://10.0.0.5")).toBe("endpoint_targets_a_private_ip");
    expect(storageEndpointSsrfReason("http://192.168.1.10")).toBe("endpoint_targets_a_private_ip");
    expect(storageEndpointSsrfReason("http://172.16.0.1")).toBe("endpoint_targets_a_private_ip");
    expect(storageEndpointSsrfReason("http://minio.internal")).toBe("endpoint_targets_a_local_host");
  });
  it("allows a private host only when explicitly opted in (on-prem MinIO)", () => {
    expect(storageEndpointSsrfReason("http://192.168.1.10:9000", true)).toBeNull();
    expect(storageEndpointSsrfReason("http://127.0.0.1:9000", true)).toBeNull();
  });
  it("rejects a non-http(s) scheme + a malformed URL", () => {
    expect(storageEndpointSsrfReason("file:///etc/passwd")).toBe("endpoint_scheme_must_be_http_or_https");
    expect(storageEndpointSsrfReason("not a url")).toBe("invalid_endpoint");
  });
});
