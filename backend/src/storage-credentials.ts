// SPDX-License-Identifier: AGPL-3.0-or-later
// storage-credentials.ts — UI-managed, encrypted-at-rest object-storage credentials + a
// storage connection-test probe (API.md §8c).
//
// WHY: until now, per-backend presign credentials had to be provisioned out-of-band as Worker
// secrets (`S3_ACCESS_KEY_ID__<REF>` / `S3_SECRET_ACCESS_KEY__<REF>`). This module lets an
// owner/admin manage them through the web UI: the SECRET access key is sealed with AES-256-GCM
// (storage-crypto.ts) under the deployment `STORAGE_ENC_KEY` and stored in the OrgDO; the
// access-key id + label are stored plaintext for display. The secret is NEVER returned by any
// API after creation — it is decrypted ONLY server-side at presign time.
//
// A filespace's `storageCredentialRef` now references a managed credential `id`. At presign time
// the gateway resolves it via `managedCredentialResolver` (decrypt) FIRST, then falls back to the
// env `S3_*__<REF>` scheme for back-compat (storage.ts `resolveStorageConfigAsync`).
//
// The connection-test endpoint does a REAL probe (PUT → GET → DELETE + LIST) against the target
// bucket using either a saved/managed credential or unsaved creds from the body, and returns a
// structured result (never throws raw) so the web "Test connection" button + non-empty-bucket
// warning can render.

import { AwsClient } from "aws4fetch";
import type { Env } from "./env";
import type { AuthedContext } from "./org-do";
import type { ManagedCredentialResolver, StorageConfig } from "./storage";
import { presignWith, requiredUploadHeaders, defaultStorageConfig, describeDefaultStorage } from "./storage";
import { sealSecret, openSecret } from "./security/storage-crypto";
import {
  RateLimiter,
  InMemoryRateLimitStore,
  tooManyRequests,
  type RateLimitResult,
} from "./security/ratelimit";

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/// Audit B16 (SSRF) — reason the admin-supplied storage endpoint is UNSAFE to probe, or null when
/// it's safe. Rejects: a non-http(s) scheme; a cloud-metadata / loopback / link-local / RFC-1918
/// host (the worker would become a proxy to internal services). `allowPrivate` (an opt-in for an
/// internal MinIO) relaxes the private-host check but never the metadata/scheme checks.
export function storageEndpointSsrfReason(endpoint: string, allowPrivate = false): string | null {
  let url: URL;
  try { url = new URL(endpoint); } catch { return "invalid_endpoint"; }
  if (url.protocol !== "https:" && url.protocol !== "http:") return "endpoint_scheme_must_be_http_or_https";
  const host = url.hostname.toLowerCase();
  // Cloud metadata services — ALWAYS blocked (the classic SSRF target), even with allowPrivate.
  if (host === "169.254.169.254" || host === "metadata.google.internal" || host === "fd00:ec2::254") {
    return "endpoint_targets_cloud_metadata";
  }
  if (allowPrivate) return null; // operator opted into an internal endpoint (e.g. on-prem MinIO)
  // Loopback / link-local / private (RFC-1918) IPv4, IPv6 loopback/ULA, and obvious local names.
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) {
    return "endpoint_targets_a_local_host";
  }
  const v4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [a, b, c] = [Number(v4[1]), Number(v4[2]), Number(v4[3])];
    if (a === 127 || a === 10 || a === 0 ||
        (a === 169 && b === 254) ||                 // link-local
        (a === 172 && b >= 16 && b <= 31) ||        // 172.16/12
        (a === 192 && b === 168) ||                 // 192.168/16
        (a === 100 && b >= 64 && b <= 127)) {       // CGNAT 100.64/10
      void c;
      return "endpoint_targets_a_private_ip";
    }
  }
  if (host === "::1" || host === "[::1]" || host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80")) {
    return "endpoint_targets_a_private_ipv6";
  }
  return null;
}

/// FROZEN CONTRACT: the safe, client-facing credential shape (never carries the secret).
export interface StorageCredential {
  id: string;
  label: string;
  accessKeyId: string;
  createdAt: number;
}

// ---------------------------------------------------------------------------------------
// Managed-credential resolver factory (wired into the presigner).
// ---------------------------------------------------------------------------------------

/// Build the resolver the presigner uses to turn a filespace's `storageCredentialRef` into a
/// DECRYPTED key pair. Returns null when the ref is NOT a managed credential id (so the presigner
/// falls back to the env `S3_*__<REF>` scheme). Throws only if a managed row exists but its secret
/// can't be decrypted (bad/missing STORAGE_ENC_KEY) — fail closed rather than sign with the wrong
/// keys. `org` is the OrgDO stub for the caller's org.
export function managedCredentialResolver(env: Env, org: OrgStub): ManagedCredentialResolver {
  return async (credentialRef: string) => {
    const row = await org.getStorageCredential(credentialRef);
    if (!row) return null; // not a managed id → env fallback
    const secretAccessKey = await openSecret(env.STORAGE_ENC_KEY, {
      iv: row.secretIv,
      ciphertext: row.secretCiphertext,
    });
    return { accessKeyId: row.accessKeyId, secretAccessKey };
  };
}

// The slice of the OrgDO stub this module needs (keeps it decoupled + testable).
export interface OrgStub {
  listStorageCredentials(): Promise<StorageCredential[]>;
  putStorageCredential(input: {
    orgId: string;
    label: string;
    accessKeyId: string;
    secretIv: string;
    secretCiphertext: string;
  }): Promise<StorageCredential>;
  getStorageCredential(id: string): Promise<
    | { id: string; accessKeyId: string; secretIv: string; secretCiphertext: string }
    | null
  >;
  spacesUsingStorageCredential(id: string): Promise<string[]>;
  deleteStorageCredential(id: string): Promise<boolean>;
}

// ---------------------------------------------------------------------------------------
// Connection-test rate limiter — the probe does real network I/O, so cap it per principal.
// In-isolate is acceptable: it's a manual, owner/admin-only "Test connection" click, not a hot
// path; the real protection is the role gate + the short-lived nature of the probe object.
// ---------------------------------------------------------------------------------------
const connTestStore = new InMemoryRateLimitStore();
const connTestLimiter = new RateLimiter(connTestStore, { capacity: 10, refillPerSec: 0.5 });

// ---------------------------------------------------------------------------------------
// Connection-test probe.
// ---------------------------------------------------------------------------------------

export interface ConnTestResult {
  reachable: boolean;
  canWrite: boolean;
  canRead: boolean;
  canDelete: boolean;
  prefixEmpty: boolean;
  sampleKeys?: string[];
  error?: string;
}

/// The fetch surface the probe needs — `fetch` plus presign. Injectable so tests can supply a
/// known-answer S3 mock with no network.
export interface ProbeDeps {
  fetch: typeof fetch;
}

const PROBE_TTL = 120; // seconds — the presigned probe URLs live briefly.

/// Build the S3 ListObjectsV2 URL for a prefix (path-style or virtual-host, max-keys capped).
function listUrl(config: StorageConfig, prefix: string, maxKeys: number): string {
  const base = config.endpoint.replace(/\/+$/, "");
  let u: URL;
  if (config.forcePathStyle ?? true) {
    u = new URL(`${base}/${config.bucket}`);
  } else {
    u = new URL(base);
    u.hostname = `${config.bucket}.${u.hostname}`;
  }
  u.searchParams.set("list-type", "2");
  if (prefix) u.searchParams.set("prefix", prefix);
  u.searchParams.set("max-keys", String(maxKeys));
  return u.toString();
}

/// Parse the `<Key>…</Key>` entries out of an S3 ListObjectsV2 XML body (we avoid a full XML dep;
/// the keys are all we surface). Returns up to `limit` keys.
function parseListedKeys(xml: string, limit: number): string[] {
  const keys: string[] = [];
  const re = /<Key>([^<]*)<\/Key>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) && keys.length < limit) keys.push(decodeXmlEntities(m[1]));
  return keys;
}

function decodeXmlEntities(s: string): string {
  return s
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

/// Run a real connection probe against `config` under `prefix`: PUT a tiny throwaway object,
/// GET it back, DELETE it, and LIST the prefix to determine emptiness + a sample. Never throws —
/// any failure is mapped into the structured result with a short `error` string. This powers the
/// web "Test connection" button and the non-empty-bucket warning.
export async function probeStorage(
  config: StorageConfig,
  prefix: string,
  deps: ProbeDeps,
): Promise<ConnTestResult> {
  const result: ConnTestResult = {
    reachable: false,
    canWrite: false,
    canRead: false,
    canDelete: false,
    prefixEmpty: true,
  };
  // Confine the test object to the target prefix; a random suffix avoids collisions/caching.
  const cleanPrefix = prefix.replace(/^\/+/, "").replace(/\/+$/, "");
  const rand = crypto.randomUUID();
  const testKey = `${cleanPrefix ? cleanPrefix + "/" : ""}.cloudfs-conntest-${rand}`;
  const body = `cloudfs-conntest ${rand}`;

  // 1. LIST the prefix first to learn reachability + emptiness (read-only; the most basic probe).
  try {
    const url = listUrl(config, cleanPrefix ? cleanPrefix + "/" : "", 8);
    const signed = await signHeaders(config, url, "GET");
    const res = await deps.fetch(signed.url, { method: "GET", headers: signed.headers });
    if (!res.ok) {
      result.error = `list_failed_${res.status}`;
      return result; // unreachable / unauthorized — stop here, nothing else will work.
    }
    result.reachable = true;
    const xml = await res.text();
    const keys = parseListedKeys(xml, 8).filter((k) => !k.includes(".cloudfs-conntest-"));
    result.prefixEmpty = keys.length === 0;
    if (keys.length > 0) result.sampleKeys = keys.slice(0, 5);
  } catch (e) {
    result.error = shortErr(e);
    return result;
  }

  // 2. PUT a tiny object (write probe).
  try {
    const putUrl = await presignWith(config, testKey, "PUT", PROBE_TTL);
    const res = await deps.fetch(putUrl, { method: "PUT", headers: requiredUploadHeaders(testKey), body });
    result.canWrite = res.ok;
    if (!res.ok && !result.error) result.error = `put_failed_${res.status}`;
  } catch (e) {
    if (!result.error) result.error = shortErr(e);
  }

  // 3. GET it back (read probe) — only meaningful if the write landed.
  if (result.canWrite) {
    try {
      const getUrl = await presignWith(config, testKey, "GET", PROBE_TTL);
      const res = await deps.fetch(getUrl, { method: "GET" });
      result.canRead = res.ok && (await res.text()) === body;
      if (!res.ok && !result.error) result.error = `get_failed_${res.status}`;
      else if (!result.canRead && !result.error) result.error = "readback_mismatch";
    } catch (e) {
      if (!result.error) result.error = shortErr(e);
    }
  }

  // 4. DELETE it (cleanup + delete probe). DELETE isn't in the presign allow-list (read/write
  //    only), so we sign the DELETE here directly off the same config.
  if (result.canWrite) {
    try {
      const del = await signHeaders(config, objectUrlFor(config, testKey), "DELETE");
      const res = await deps.fetch(del.url, { method: "DELETE", headers: del.headers });
      // S3 returns 204 on delete; treat any 2xx as success.
      result.canDelete = res.ok;
      if (!res.ok && !result.error) result.error = `delete_failed_${res.status}`;
    } catch (e) {
      if (!result.error) result.error = shortErr(e);
    }
  }

  return result;
}

function shortErr(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  return msg.slice(0, 200);
}

// The probe needs GET-on-a-list-URL and DELETE, neither of which `presignWith` mints (it's
// confined to GET/HEAD/PUT on object keys). These are server-side requests, so they are signed
// with Authorization HEADERS, not presigned query strings: R2 refuses query-string-signed
// ListObjectsV2 when a temporary credential's X-Amz-Security-Token is in the query
// (501 NotImplemented), while header signing works for every operation. The same aws4fetch
// dialect `presignWith` uses keeps provider behavior identical. Object PUT/GET above keep the
// presigned form because that is exactly what clients receive and R2 accepts it with a token.
async function signHeaders(config: StorageConfig, fullUrl: string, method: "GET" | "DELETE"): Promise<{ url: string; headers: Record<string, string> }> {
  const aws = new AwsClient({
    accessKeyId: config.accessKeyId,
    secretAccessKey: config.secretAccessKey,
    sessionToken: config.sessionToken,
    region: config.region,
    service: "s3",
  });
  const signed = await aws.sign(fullUrl, { method });
  const headers: Record<string, string> = {};
  signed.headers.forEach((value, name) => { headers[name] = value; });
  return { url: signed.url, headers };
}

function objectUrlFor(config: StorageConfig, key: string): string {
  const base = config.endpoint.replace(/\/+$/, "");
  if (config.forcePathStyle ?? true) return `${base}/${config.bucket}/${key}`;
  const u = new URL(`${base}/${key}`);
  u.hostname = `${config.bucket}.${u.hostname}`;
  return u.toString();
}

// ---------------------------------------------------------------------------------------
// HTTP handler — /v1/orgs/:org/storage-credentials[/:id] and /v1/orgs/:org/storage/test.
// Mounted by the gateway, which has already authenticated the principal + supplied the org role.
// ---------------------------------------------------------------------------------------

/// Default probe deps (real network fetch). Tests pass their own.
const defaultProbeDeps: ProbeDeps = { fetch: (input, init) => fetch(input, { ...init, redirect: "manual", signal: AbortSignal.timeout(5000) }) };

export interface StorageCredentialsDeps {
  org: OrgStub;
  /// Probe injection seam (known-answer S3 mock in tests).
  probeDeps?: ProbeDeps;
  /// Resolve a saved/managed credential id → decrypted key pair (for the test endpoint when the
  /// body names a `credentialId`). Defaults to the managed store via STORAGE_ENC_KEY.
  resolveManaged?: ManagedCredentialResolver;
  /// Rate-limit key for the connection-test route (default: the principal). Injectable for tests.
  rateKey?: string;
}

/// Handle the storage-credentials + storage-test routes. `rest` is the path AFTER /v1/orgs/:org
/// (e.g. ["storage-credentials"] or ["storage","test"]). Returns null if the path isn't ours.
export async function handleStorageCredentialsRequest(
  req: Request,
  env: Env,
  ctx: AuthedContext,
  rest: string[],
  orgId: string,
  deps: StorageCredentialsDeps,
): Promise<Response | null> {
  const isAdmin = ctx.orgRole === "owner" || ctx.orgRole === "admin";
  const probeDeps = deps.probeDeps ?? defaultProbeDeps;

  // Deployment storage is configured once by the operator. Return only its safe descriptor;
  // validation uses the stored secrets without copying them into a per-filespace credential.
  if (rest[0] === "storage" && rest[1] === "default" && rest.length <= 3) {
    if (!isAdmin) return json({ error: "forbidden: admin required" }, 403);
    const descriptor = describeDefaultStorage(env, new URL(req.url).protocol === "https:");
    if (rest.length === 2 && req.method === "GET") return json(descriptor);
    if (rest[2] !== "validate" || req.method !== "POST") return json({ error: "method not allowed" }, 405);
    const rl = await connTestLimiter.check(deps.rateKey ?? ctx.principalUserId);
    if (!rl.allowed) return tooManyRequests(rl);
    if (!descriptor.configured) return json({ reachable: false, canWrite: false, canRead: false, canDelete: false, prefixEmpty: true, error: descriptor.problems.join(" ") }, 200);
    return json(await probeStorage(defaultStorageConfig(env), `.cloudfs-probes/${orgId}`, probeDeps));
  }

  // ---- /v1/orgs/:org/storage/test ----
  if (rest[0] === "storage" && rest[1] === "test") {
    if (req.method !== "POST") return json({ error: "method not allowed" }, 405);
    if (!isAdmin) return json({ error: "forbidden: admin required" }, 403);
    const rl: RateLimitResult = await connTestLimiter.check(deps.rateKey ?? ctx.principalUserId);
    if (!rl.allowed) return tooManyRequests(rl);
    return await handleConnTest(req, env, orgId, deps, probeDeps);
  }

  // ---- /v1/orgs/:org/storage-credentials[/:id] ----
  if (rest[0] !== "storage-credentials") return null;
  const id = rest[1] ? decodeURIComponent(rest[1]) : null;

  // All credential routes are owner/admin only.
  if (!isAdmin) return json({ error: "forbidden: admin required" }, 403);

  try {
    if (req.method === "GET" && !id) {
      const credentials = await deps.org.listStorageCredentials();
      return json({ credentials });
    }
    if (req.method === "POST" && !id) {
      const b = (await req.json().catch(() => ({}))) as {
        label?: unknown;
        accessKeyId?: unknown;
        secretAccessKey?: unknown;
      };
      const label = typeof b.label === "string" ? b.label.trim() : "";
      const accessKeyId = typeof b.accessKeyId === "string" ? b.accessKeyId.trim() : "";
      const secretAccessKey = typeof b.secretAccessKey === "string" ? b.secretAccessKey : "";
      if (!label || !accessKeyId || !secretAccessKey) {
        return json({ error: "label, accessKeyId and secretAccessKey are required" }, 400);
      }
      // Seal the secret BEFORE it touches the DO. Fail closed (500) if STORAGE_ENC_KEY is unset.
      let sealed;
      try {
        sealed = await sealSecret(env.STORAGE_ENC_KEY, secretAccessKey);
      } catch (e) {
        return json({ error: "storage_enc_key_unconfigured", detail: shortErr(e) }, 500);
      }
      const created = await deps.org.putStorageCredential({
        orgId,
        label,
        accessKeyId,
        secretIv: sealed.iv,
        secretCiphertext: sealed.ciphertext,
      });
      // Echo back the SAFE projection only (never the secret).
      return json(created, 201);
    }
    if (req.method === "DELETE" && id) {
      const spaces = await deps.org.spacesUsingStorageCredential(id);
      if (spaces.length > 0) {
        return json({ error: "credential_in_use", spaces }, 409);
      }
      const removed = await deps.org.deleteStorageCredential(id);
      if (!removed) return json({ error: "not found" }, 404);
      return new Response(null, { status: 204 });
    }
    return json({ error: "method not allowed" }, 405);
  } catch (e) {
    return json({ error: shortErr(e) }, 500);
  }
}

/// Build a StorageConfig for the test probe from the request body, resolving creds in this order:
///   1. body.credentialId  → the managed (decrypt) or env-saved credential
///   2. body.accessKeyId + body.secretAccessKey → unsaved creds straight from the body
/// then run the probe and return the structured result.
async function handleConnTest(
  req: Request,
  env: Env,
  orgId: string,
  deps: StorageCredentialsDeps,
  probeDeps: ProbeDeps,
): Promise<Response> {
  let b: {
    endpoint?: unknown;
    region?: unknown;
    bucket?: unknown;
    forcePathStyle?: unknown;
    keyPrefix?: unknown;
    credentialId?: unknown;
    accessKeyId?: unknown;
    secretAccessKey?: unknown;
  };
  try {
    b = (await req.json()) as typeof b;
  } catch {
    return json({ error: "invalid_body" }, 400);
  }
  const endpoint = typeof b.endpoint === "string" ? b.endpoint.trim() : "";
  const region = typeof b.region === "string" && b.region.trim() ? b.region.trim() : "auto";
  const bucket = typeof b.bucket === "string" ? b.bucket.trim() : "";
  const forcePathStyle = typeof b.forcePathStyle === "boolean" ? b.forcePathStyle : true;
  const keyPrefix = typeof b.keyPrefix === "string" ? b.keyPrefix : "";
  if (!endpoint || !bucket) {
    return json({ reachable: false, canWrite: false, canRead: false, canDelete: false, prefixEmpty: true, error: "endpoint and bucket are required" }, 400);
  }
  // Audit B16 (SSRF): the connection-test probe fetches the ADMIN-SUPPLIED endpoint. Without a
  // guard, an admin could point it at an internal URL (cloud metadata 169.254.169.254, localhost,
  // RFC-1918) and use the worker as a proxy to read internal services. Reject endpoints that
  // resolve to a private/loopback/link-local host (an https public S3 endpoint is the legit case).
  // A deployer who genuinely runs an internal MinIO opts in via STORAGE_PROBE_ALLOW_PRIVATE=1.
  const allowPrivate = /^(1|true|yes)$/i.test(((env as { STORAGE_PROBE_ALLOW_PRIVATE?: string }).STORAGE_PROBE_ALLOW_PRIVATE ?? "").trim());
  const ssrf = storageEndpointSsrfReason(endpoint, allowPrivate);
  if (ssrf) {
    return json({ reachable: false, canWrite: false, canRead: false, canDelete: false, prefixEmpty: true, error: ssrf }, 400);
  }

  // Resolve credentials.
  let accessKeyId: string;
  let secretAccessKey: string;
  const credentialId = typeof b.credentialId === "string" && b.credentialId.trim() ? b.credentialId.trim() : null;
  if (credentialId) {
    const resolve = deps.resolveManaged ?? managedCredentialResolver(env, deps.org);
    let hit;
    try {
      hit = await resolve(credentialId);
    } catch (e) {
      return json({ reachable: false, canWrite: false, canRead: false, canDelete: false, prefixEmpty: true, error: shortErr(e) }, 200);
    }
    if (!hit) {
      return json({ reachable: false, canWrite: false, canRead: false, canDelete: false, prefixEmpty: true, error: "unknown_credential" }, 200);
    }
    accessKeyId = hit.accessKeyId;
    secretAccessKey = hit.secretAccessKey;
  } else if (typeof b.accessKeyId === "string" && b.accessKeyId.trim() && typeof b.secretAccessKey === "string" && b.secretAccessKey) {
    accessKeyId = b.accessKeyId.trim();
    secretAccessKey = b.secretAccessKey;
  } else {
    return json({ reachable: false, canWrite: false, canRead: false, canDelete: false, prefixEmpty: true, error: "credentialId or accessKeyId+secretAccessKey required" }, 400);
  }

  const config: StorageConfig = { endpoint, region, bucket, accessKeyId, secretAccessKey, forcePathStyle };
  const result = await probeStorage(config, keyPrefix, probeDeps);
  return json(result, 200);
}
