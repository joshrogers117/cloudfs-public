// SPDX-License-Identifier: AGPL-3.0-or-later
// storage.ts — bring-your-own S3-COMPATIBLE object storage (open-source / self-host).
//
// cloud-fs never proxies object bytes (SPEC §4.4): the macOS client streams media
// DIRECTLY to/from the bucket via short-lived presigned URLs minted here. Historically
// the gateway had ONE global backend (the `S3_*` env vars) and `presign()` signed every
// space's URLs against it. This module GENERALIZES that to a PER-FILESPACE storage backend
// so a self-hoster can point different filespaces at different S3-compatible providers —
// Cloudflare R2, AWS S3, Backblaze B2, MinIO, Wasabi, Ceph — each with its own
// endpoint / region / bucket / credentials.
//
// KEY DECISIONS
//   - SigV4 via `aws4fetch` (already a dependency; Workers-native, WebCrypto-backed, no
//     Node polyfills). Every provider above speaks the S3 SigV4 presign dialect, so ONE
//     code path covers all of them — the only knobs are endpoint, region, bucket, and
//     path-vs-vhost addressing.
//   - R2 stays a first-class citizen TWO ways: (1) as a normal S3-compatible backend via
//     its S3 endpoint (`https://<acct>.r2.cloudflarestorage.com`, region "auto"), which is
//     what presigning needs; and (2) the NATIVE R2 binding remains how the DO reads/writes
//     audit archives directly (env.AUDIT_BUCKET) — bindings can't mint cross-origin
//     presigned URLs, so the data plane that the *client* touches always uses (1).
//   - SECRETS STAY OUT OF THE REGISTRY. A space's registry row never stores an access key.
//     It stores a `credentialRef` naming a pair of Worker secrets
//     (`S3_ACCESS_KEY_ID__<REF>` / `S3_SECRET_ACCESS_KEY__<REF>`); absent a ref we fall back
//     to the default `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY`. Temporary credentials
//     include `S3_SESSION_TOKEN` (or the matching `__<REF>` binding). Credentials are
//     resolved from `env` at presign time and never persisted to a DO.

import { AwsClient } from "aws4fetch";
import type { Env } from "./env";

/// TTL floor/ceiling and method allow-list (SPEC §4.4; docs/security.md F8). The gateway
/// already enforces these; the helper refuses obviously-overbroad input as defense-in-depth.
const TTL_MIN = 60;
const TTL_MAX = 900; // minute-scale: a leaked URL dies fast
const ALLOWED_METHODS = new Set(["GET", "HEAD", "PUT"]);

/// Resolved secret credentials, including the optional temporary-session token.
export interface StorageCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  /// Optional third credential for temporary S3/R2 sessions; never public config.
  sessionToken?: string;
}

/// Fully resolved backend, assembled from the secret-free registry and secret
/// credential source at signing time. This combined config is never persisted.
export interface StorageConfig extends StorageCredentials {
  /// Internal provenance from the trusted resolver, never the public descriptor.
  /// Native default-bucket access must additionally match the full backend identity.
  credentialSource?: "deployment-default";
  /// S3 endpoint origin, NO bucket/key, e.g. "https://<acct>.r2.cloudflarestorage.com",
  /// "https://s3.us-east-1.amazonaws.com", "https://s3.us-west-002.backblazeb2.com",
  /// "http://127.0.0.1:9000" (MinIO).
  endpoint: string;
  /// SigV4 region. R2 uses "auto"; AWS/B2/Wasabi use a real region; MinIO/Ceph ignore it
  /// but a value is still required for the signature (use "us-east-1" by convention).
  region: string;
  /// Bucket name.
  bucket: string;
  /// Path-style addressing (`<endpoint>/<bucket>/<key>`) vs virtual-host
  /// (`<bucket>.<endpoint>/<key>`). MinIO/Ceph/R2-S3 want path-style; AWS S3 / B2 / Wasabi
  /// work with either but we keep path-style by default for portability. Default: true.
  forcePathStyle?: boolean;
}

export type DefaultStorageEnv = Partial<Pick<Env, "S3_ENDPOINT" | "S3_REGION" | "S3_BUCKET" | "S3_ACCESS_KEY_ID" | "S3_SECRET_ACCESS_KEY" | "STORAGE_PROBE_ALLOW_PRIVATE">>;

/** Safe discovery for the create-filespace form. Configuration is not a connectivity test. */
export function describeDefaultStorage(env: DefaultStorageEnv, isHttps = false) {
  const endpoint = env.S3_ENDPOINT?.trim() ?? "";
  const bucket = env.S3_BUCKET?.trim() ?? "";
  const region = env.S3_REGION?.trim() || "auto";
  const problems: string[] = [];
  let host = "";
  try {
    const url = new URL(endpoint);
    host = url.hostname;
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== "/") {
      problems.push("Storage endpoint must be an HTTP(S) origin without a path or credentials.");
    }
    const local = host === "localhost" || host.endsWith(".local") || host === "127.0.0.1" || host === "[::1]";
    if (isHttps && (url.protocol !== "https:" || local) && !/^(1|true|yes)$/i.test(env.STORAGE_PROBE_ALLOW_PRIVATE ?? "")) {
      problems.push("Configure a public HTTPS storage endpoint before creating a filespace.");
    }
  } catch { problems.push("Configure the deployment storage endpoint."); }
  if (!bucket || /change-me|your[_-]|placeholder/i.test(bucket + endpoint)) problems.push("Configure the deployment bucket.");
  if (!env.S3_ACCESS_KEY_ID || !env.S3_SECRET_ACCESS_KEY) problems.push("Configure the deployment storage access keys.");
  const provider = host.endsWith(".r2.cloudflarestorage.com") ? "r2" : (host === "localhost" || host === "127.0.0.1") ? "minio" : "s3";
  return { configured: problems.length === 0, provider, endpoint, region, bucket, forcePathStyle: true, problems };
}

/// The PERSISTED, SECRET-FREE per-filespace storage descriptor (lives in the OrgDO `spaces`
/// registry). `provider` is descriptive ("r2" | "s3" | "b2" | "minio" | "wasabi" | "ceph" |
/// any string). When `endpoint`/`region`/`bucket` are absent the gateway falls back to the
/// deployment default backend (the `S3_*` env), preserving the single-backend behaviour.
export interface SpaceStorageDescriptor {
  provider?: string | null;
  endpoint?: string | null;
  region?: string | null;
  bucket?: string | null;
  forcePathStyle?: boolean | null;
  /// Names the credential pair in env (`S3_ACCESS_KEY_ID__<ref>` /
  /// `S3_SECRET_ACCESS_KEY__<ref>`). Absent => the default `S3_*` credentials. The ref is
  /// uppercased + non-alnum stripped before lookup so a human-friendly label is safe.
  credentialRef?: string | null;
}

/// Normalize a credentialRef into the env-var SUFFIX used to look the secrets up. Keeps the
/// lookup deterministic + injection-safe: only [A-Z0-9_] survive.
export function credentialEnvSuffix(ref: string): string {
  return ref.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

/// Resolve the access-key pair for a space from env, honoring an optional credentialRef.
/// Throws if a referenced secret is missing (fail-closed — never silently sign with the
/// default keys when a ref was requested, which could cross tenants/providers).
export function resolveCredentials(
  env: Record<string, unknown>,
  credentialRef?: string | null,
): StorageCredentials {
  if (credentialRef) {
    const suffix = credentialEnvSuffix(credentialRef);
    const id = env[`S3_ACCESS_KEY_ID__${suffix}`];
    const secret = env[`S3_SECRET_ACCESS_KEY__${suffix}`];
    if (typeof id !== "string" || !id || typeof secret !== "string" || !secret) {
      throw new Error(`storage: missing credentials for ref "${credentialRef}" (expected S3_ACCESS_KEY_ID__${suffix} / S3_SECRET_ACCESS_KEY__${suffix})`);
    }
    return { accessKeyId: id, secretAccessKey: secret, ...sessionCredential(env[`S3_SESSION_TOKEN__${suffix}`]) };
  }
  const id = env.S3_ACCESS_KEY_ID;
  const secret = env.S3_SECRET_ACCESS_KEY;
  if (typeof id !== "string" || !id || typeof secret !== "string" || !secret) {
    throw new Error("storage: default S3 credentials (S3_ACCESS_KEY_ID / S3_SECRET_ACCESS_KEY) are not configured");
  }
  return { accessKeyId: id, secretAccessKey: secret, ...sessionCredential(env.S3_SESSION_TOKEN) };
}

function sessionCredential(token: unknown): Pick<StorageCredentials, "sessionToken"> {
  if (token === undefined || token === "") return {};
  if (typeof token !== "string") throw new Error("storage: invalid S3 session token");
  return { sessionToken: token };
}

/// A resolver that maps a filespace's `credentialRef` to a DECRYPTED access-key pair held in the
/// UI-managed credential store (org-do.ts + storage-crypto.ts). Returns null when the ref does
/// NOT name a managed credential (so the caller falls back to the env `S3_*__<REF>` scheme).
/// Injected by the gateway (which owns the OrgDO + STORAGE_ENC_KEY); storage.ts stays store-free.
export interface ManagedCredentialResolver {
  (credentialRef: string): Promise<StorageCredentials | null>;
}

/// Resolve credentials honoring the MANAGED store FIRST, then the env fallback (fail closed).
/// A `credentialRef` is looked up in the managed store; if found, its decrypted keys win. If the
/// managed lookup returns null (not a managed id, or store unavailable) we fall back to the env
/// `S3_ACCESS_KEY_ID__<REF>` / `S3_SECRET_ACCESS_KEY__<REF>` pair (back-compat). With no ref we
/// use the default `S3_*` keys. Throws (fail closed) when a ref resolves to NEITHER source.
export async function resolveCredentialsManagedFirst(
  env: Record<string, unknown>,
  credentialRef: string | null | undefined,
  managed?: ManagedCredentialResolver,
): Promise<StorageCredentials> {
  if (credentialRef && managed) {
    const hit = await managed(credentialRef);
    if (hit) return hit;
  }
  // No managed hit → the existing env-secret scheme (throws if a referenced pair is missing).
  return resolveCredentials(env, credentialRef ?? null);
}

/// The deployment-DEFAULT backend assembled from the `S3_*` env (back-compat). This is what
/// every space that hasn't overridden its storage uses. In prod the `S3_ENDPOINT` typically
/// points at R2's S3 endpoint; locally it's MinIO.
export function defaultStorageConfig(env: Env): StorageConfig {
  const credentials = resolveCredentials(env as unknown as Record<string, unknown>, null);
  return {
    endpoint: env.S3_ENDPOINT,
    region: (env as { S3_REGION?: string }).S3_REGION || "auto",
    bucket: env.S3_BUCKET,
    ...credentials,
    credentialSource: "deployment-default",
    forcePathStyle: true,
  };
}

/// Merge a (secret-free) per-space descriptor over the deployment default to produce the
/// effective StorageConfig. A descriptor that omits endpoint/region/bucket inherits the
/// default backend (single-backend deployments keep working with no per-space config). When
/// the descriptor DOES name a backend, its credentialRef (if any) selects the key pair.
export function resolveStorageConfig(env: Env, descriptor?: SpaceStorageDescriptor | null): StorageConfig {
  if (!descriptor || (!descriptor.endpoint && !descriptor.bucket && !descriptor.region && !descriptor.credentialRef && descriptor.forcePathStyle == null)) {
    return defaultStorageConfig(env);
  }
  const def = { endpoint: env.S3_ENDPOINT, region: env.S3_REGION || "auto", bucket: env.S3_BUCKET, forcePathStyle: true };
  // If the descriptor names its OWN backend, resolve its credentials; else keep default keys.
  const creds =
    descriptor.credentialRef || descriptor.endpoint
      ? resolveCredentials(env as unknown as Record<string, unknown>, descriptor.credentialRef ?? null)
      : resolveCredentials(env as unknown as Record<string, unknown>, null);
  return {
    endpoint: descriptor.endpoint || def.endpoint,
    region: descriptor.region || def.region,
    bucket: descriptor.bucket || def.bucket,
    ...creds,
    credentialSource: descriptor.credentialRef ? undefined : "deployment-default",
    forcePathStyle: descriptor.forcePathStyle ?? def.forcePathStyle ?? true,
  };
}

/// Async sibling of `resolveStorageConfig` that resolves a `credentialRef` via the UI-MANAGED
/// store FIRST (decrypting the secret), then falls back to the env `S3_*__<REF>` scheme. Used at
/// presign time by the gateway (which can talk to the OrgDO). A descriptor with no own backend
/// inherits the deployment default exactly as the sync path does. Fail-closed: an unresolvable
/// ref throws.
export async function resolveStorageConfigAsync(
  env: Env,
  descriptor: SpaceStorageDescriptor | null | undefined,
  managed?: ManagedCredentialResolver,
): Promise<StorageConfig> {
  if (!descriptor || (!descriptor.endpoint && !descriptor.bucket && !descriptor.region && !descriptor.credentialRef && descriptor.forcePathStyle == null)) {
    return defaultStorageConfig(env);
  }
  const def = { endpoint: env.S3_ENDPOINT, region: env.S3_REGION || "auto", bucket: env.S3_BUCKET, forcePathStyle: true };
  const creds =
    descriptor.credentialRef || descriptor.endpoint
      ? await resolveCredentialsManagedFirst(
          env as unknown as Record<string, unknown>,
          descriptor.credentialRef ?? null,
          managed,
        )
      : resolveCredentials(env as unknown as Record<string, unknown>, null);
  return {
    endpoint: descriptor.endpoint || def.endpoint,
    region: descriptor.region || def.region,
    bucket: descriptor.bucket || def.bucket,
    ...creds,
    credentialSource: descriptor.credentialRef ? undefined : "deployment-default",
    forcePathStyle: descriptor.forcePathStyle ?? def.forcePathStyle ?? true,
  };
}

/// Build the object URL for a key under a backend, honoring path-style vs virtual-host. We
/// build the raw `<endpoint>/<bucket>/<key>` string and let `new URL()` normalize it (this
/// matches the original single-backend presigner — `aws4fetch` then signs the canonicalized
/// path). Path-safe characters like the `::` in a `<org>::<space>` prefix stay literal, so the
/// signed URL format is unchanged from before. The upstream gateway already rejects `..` and
/// leading-`/` keys; presignWith re-checks as defense-in-depth.
export function objectUrl(config: StorageConfig, key: string): string {
  const base = config.endpoint.replace(/\/+$/, "");
  // Object keys are data, never URL syntax. Encode each path component before
  // constructing a URL so percent-encoded dot segments, '?' and '#' cannot
  // change the resource authorized by the namespace. Preserve ':' for existing
  // filespace URLs/signatures; it has no structural meaning in a path segment.
  const path = key.split("/").map(part => encodeURIComponent(part).replace(/%3A/gi, ":")).join("/");
  if (config.forcePathStyle ?? true) {
    return new URL(`${base}/${encodeURIComponent(config.bucket)}/${path}`).toString();
  }
  // virtual-host: bucket as a subdomain of the endpoint host.
  const u = new URL(`${base}/${path}`);
  u.hostname = `${config.bucket}.${u.hostname}`;
  return u.toString();
}

/** Canonical block keys bind PUT bodies to their ciphertext SHA-256. Legacy
 * non-content-addressed imports have no inferred checksum and cannot replace
 * committed objects. Callers must forward these headers to the byte transport. */
export function requiredUploadHeaders(key: string): Record<string, string> {
  const hash = key.slice(key.lastIndexOf("/") + 1);
  if (!/^[0-9a-f]{64}$/.test(hash)) return { "if-none-match": "*" };
  return { "if-none-match": "*", "x-amz-checksum-sha256": btoa(String.fromCharCode(...hash.match(/../g)!.map(byte => parseInt(byte, 16)))) };
}

/// Core presigner: mint a short-lived S3 SigV4 presigned URL against an EXPLICIT backend.
/// Provider-agnostic — works for R2 (S3 endpoint), AWS S3, Backblaze B2, MinIO, Wasabi, Ceph.
export async function presignWith(
  config: StorageConfig,
  key: string,
  method: string,
  expiresIn: number,
  contentLength?: number,
): Promise<string> {
  return await presignUsingClient(awsClientFor(config), config, key, method, expiresIn, contentLength);
}

async function presignUsingClient(aws: AwsClient, config: StorageConfig, key: string, method: string,
  expiresIn: number, contentLength?: number): Promise<string> {
  const verb = method.toUpperCase();
  if (!ALLOWED_METHODS.has(verb)) throw new Error(`presign: method not allowed: ${verb}`);
  if (key.includes("..") || key.startsWith("/")) throw new Error("presign: illegal key");
  if (!Number.isFinite(expiresIn)) throw new Error("presign: invalid expiry");
  const ttl = Math.min(Math.max(Math.floor(expiresIn), TTL_MIN), TTL_MAX);
  const u = new URL(objectUrl(config, key));
  u.searchParams.set("X-Amz-Expires", String(ttl));

  const headers = verb === "PUT" ? requiredUploadHeaders(key) : {};
  if (verb === "PUT" && typeof contentLength === "number" && Number.isFinite(contentLength) && contentLength >= 0) {
    headers["content-length"] = String(Math.floor(contentLength));
  }
  const signed = await aws.sign(u.toString(), {
    method: verb, headers, aws: { signQuery: true, allHeaders: true },
  });
  return signed.url;
}

export interface PresignEntry { key: string; method: string; contentLength?: number }
export interface PresignResult { key: string; url?: string; headers?: Record<string, string>; verificationUrl?: string; error?: string }
/** One signer/key cache per request; bounded crypto fan-out, ordered results. */
export async function presignManyWith(config: StorageConfig, entries: PresignEntry[], expiresIn: number): Promise<PresignResult[]> {
  if (entries.length > 256) throw new Error("presign: too many keys");
  const aws = awsClientFor(config), results: PresignResult[] = [];
  for (let i = 0; i < entries.length; i += 16) {
    results.push(...await Promise.all(entries.slice(i, i + 16).map(async entry => {
      try { return { key: entry.key, url: await presignUsingClient(aws, config, entry.key, entry.method, expiresIn, entry.contentLength),
        ...(entry.method.toUpperCase() === "PUT" ? { headers: requiredUploadHeaders(entry.key) } : {}) }; }
      catch (e) { return { key: entry.key, error: e instanceof Error ? e.message : "presign failed" }; }
    })));
  }
  return results;
}

// ===========================================================================================
// PREFIX-SCOPED SWEEP PRIMITIVES (purge): list + batch-delete objects under ONE exact prefix.
//
// SAFETY CONTRACT (this is the data-destroying path — read this before touching it):
//   - Both helpers REQUIRE a non-empty `prefix`. There is NO way to list or delete the whole
//     bucket through this API: an empty/whitespace/`/`-leading prefix THROWS. ListObjectsV2 is
//     always sent with `prefix=<prefix>`; DeleteObjects ASSERTS every key `.startsWith(prefix)`
//     before a single key is put on the wire. A key outside the prefix throws (fail closed) and
//     NOTHING is deleted in that call.
//   - The prefix the caller passes is built by the gateway/DO from the TRUSTED orgId+spaceId
//     (`blocks/<org>::<space>/`), never from request input. These helpers re-validate it but the
//     authority for "what prefix" lives at the call site (filespace-do.ts purge sweep).
//   - Same aws4fetch SigV4 dialect + the same StorageConfig the presigner uses, so every provider
//     (R2 / AWS S3 / Backblaze B2 / MinIO / Wasabi / Ceph) is covered by one code path.
// ===========================================================================================

const LIST_MAX_KEYS = 1000; // S3 ListObjectsV2 hard cap per page.
const DELETE_BATCH_MAX = 1000; // S3 DeleteObjects hard cap per call.

export interface ListObjectsPage {
  /// Object keys under the prefix (each is GUARANTEED to start with the requested prefix —
  /// `listObjects` filters out any pathological key the server returns that doesn't, so the
  /// caller can never act on an out-of-prefix key even if a backend misbehaves).
  keys: string[];
  /// Opaque continuation token to fetch the next page, or null when this was the last page.
  nextContinuationToken: string | null;
}

/// Validate + normalize a sweep prefix. THROWS (fail closed) on anything that could broaden the
/// scope to the whole bucket: empty, whitespace-only, or a leading "/" (which after the
/// path-style join would address the bucket root). Returns the trimmed prefix unchanged otherwise
/// — we do NOT silently coerce, so an unexpected shape surfaces as an error rather than a wide sweep.
function assertSweepPrefix(prefix: string): string {
  if (typeof prefix !== "string") throw new Error("sweep: prefix required");
  const p = prefix;
  if (p.trim().length === 0) throw new Error("sweep: refusing empty prefix (would scope to whole bucket)");
  if (p.startsWith("/")) throw new Error("sweep: refusing leading-slash prefix");
  if (p.includes("..")) throw new Error("sweep: illegal prefix");
  return p;
}

/// Build the bucket-level base URL (no key) for list/batch-delete, honoring path-style vs vhost.
function bucketUrl(config: StorageConfig): URL {
  const base = config.endpoint.replace(/\/+$/, "");
  if (config.forcePathStyle ?? true) {
    return new URL(`${base}/${config.bucket}`);
  }
  const u = new URL(base);
  u.hostname = `${config.bucket}.${u.hostname}`;
  return u;
}

function awsClientFor(config: StorageConfig): AwsClient {
  return new AwsClient({
    accessKeyId: config.accessKeyId,
    secretAccessKey: config.secretAccessKey,
    sessionToken: config.sessionToken,
    region: config.region,
    service: "s3",
  });
}

function decodeXmlEntities(s: string): string {
  return s
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

/// List ONE page of objects strictly under `prefix` (ListObjectsV2). `prefix` is REQUIRED and
/// validated (`assertSweepPrefix`) — there is no unprefixed list. Defense in depth: any returned
/// key that does NOT start with the prefix is dropped from the page (a misbehaving/compromised
/// backend can never hand us an out-of-prefix key to delete). `fetchImpl` is injectable so tests
/// drive a fake S3 with no network. Throws on a non-2xx response (caller decides retry/abort).
export async function listObjects(
  config: StorageConfig,
  prefix: string,
  continuationToken: string | null | undefined,
  fetchImpl?: typeof fetch,
): Promise<ListObjectsPage> {
  const safePrefix = assertSweepPrefix(prefix);
  const aws = awsClientFor(config);
  const u = bucketUrl(config);
  u.searchParams.set("list-type", "2");
  u.searchParams.set("prefix", safePrefix); // REQUIRED — never list the whole bucket.
  u.searchParams.set("max-keys", String(LIST_MAX_KEYS));
  if (continuationToken) u.searchParams.set("continuation-token", continuationToken);

  const doFetch = fetchImpl ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
  const signed = await aws.sign(u.toString(), { method: "GET" });
  const res = await doFetch(signed.url, { method: "GET", headers: signed.headers });
  if (!res.ok) throw new Error(`listObjects: ${res.status} ${await safeText(res)}`);
  const xml = await res.text();

  const keys: string[] = [];
  const re = /<Key>([^<]*)<\/Key>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml))) {
    const key = decodeXmlEntities(m[1]);
    // Defense in depth: even though we asked S3 for `prefix=`, refuse to surface any key the
    // server returns that isn't under it. A delete can then NEVER see an out-of-prefix key.
    if (key.startsWith(safePrefix)) keys.push(key);
  }
  const truncated = /<IsTruncated>\s*true\s*<\/IsTruncated>/i.test(xml);
  let nextToken: string | null = null;
  if (truncated) {
    const tm = /<NextContinuationToken>([^<]*)<\/NextContinuationToken>/.exec(xml);
    nextToken = tm ? decodeXmlEntities(tm[1]) : null;
  }
  return { keys, nextContinuationToken: nextToken };
}

export interface DeleteObjectsResult {
  /// Keys S3 confirmed deleted (or that were already absent — DeleteObjects is idempotent).
  deleted: string[];
  /// Per-key errors S3 reported in the multi-delete response, if any.
  errors: { key: string; code: string; message: string }[];
}

/// XML-escape a key for the DeleteObjects request body.
function xmlEscape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/// Batch-delete up to 1000 keys (S3 DeleteObjects). EVERY key is asserted to start with `prefix`
/// BEFORE anything is sent — a single out-of-prefix key throws and NOTHING is deleted (fail
/// closed). `prefix` is required + validated. Idempotent: deleting an already-gone key is a
/// no-op, so a crash-resumed sweep that re-lists+re-deletes is harmless. `fetchImpl` injectable
/// for tests. Throws on a non-2xx HTTP response; per-key S3 errors come back in `errors`.
export async function deleteObjects(
  config: StorageConfig,
  prefix: string,
  keys: string[],
  fetchImpl?: typeof fetch,
): Promise<DeleteObjectsResult> {
  const safePrefix = assertSweepPrefix(prefix);
  if (keys.length === 0) return { deleted: [], errors: [] };
  if (keys.length > DELETE_BATCH_MAX) {
    throw new Error(`deleteObjects: batch too large (${keys.length} > ${DELETE_BATCH_MAX})`);
  }
  // THE CRITICAL ASSERTION: refuse to delete anything not under this space's prefix. This runs
  // before the request body is built, so an out-of-prefix key never reaches the wire.
  for (const k of keys) {
    if (typeof k !== "string" || !k.startsWith(safePrefix)) {
      throw new Error(`deleteObjects: key escapes prefix (refusing to delete) prefix=${safePrefix}`);
    }
  }

  const body =
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<Delete><Quiet>false</Quiet>` +
    keys.map((k) => `<Object><Key>${xmlEscape(k)}</Key></Object>`).join("") +
    `</Delete>`;
  // S3 requires a Content-MD5 on DeleteObjects; aws4fetch signs the body so a per-request SHA256
  // covers integrity for SigV4. Build the bucket URL with the `?delete` subresource.
  const aws = awsClientFor(config);
  const u = bucketUrl(config);
  u.searchParams.set("delete", "");
  const md5 = await contentMd5(body);
  const doFetch = fetchImpl ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
  const signed = await aws.sign(u.toString(), {
    method: "POST",
    headers: { "content-type": "application/xml", "content-md5": md5 },
    body,
  });
  const res = await doFetch(signed.url, { method: "POST", headers: signed.headers, body });
  if (!res.ok) throw new Error(`deleteObjects: ${res.status} ${await safeText(res)}`);
  const xml = await res.text();

  const deleted: string[] = [];
  const errors: { key: string; code: string; message: string }[] = [];
  const delRe = /<Deleted>([\s\S]*?)<\/Deleted>/g;
  let dm: RegExpExecArray | null;
  while ((dm = delRe.exec(xml))) {
    const km = /<Key>([^<]*)<\/Key>/.exec(dm[1]);
    if (km) deleted.push(decodeXmlEntities(km[1]));
  }
  const errRe = /<Error>([\s\S]*?)<\/Error>/g;
  let em: RegExpExecArray | null;
  while ((em = errRe.exec(xml))) {
    const seg = em[1];
    const km = /<Key>([^<]*)<\/Key>/.exec(seg);
    const cm = /<Code>([^<]*)<\/Code>/.exec(seg);
    const mm = /<Message>([^<]*)<\/Message>/.exec(seg);
    errors.push({
      key: km ? decodeXmlEntities(km[1]) : "",
      code: cm ? cm[1] : "Unknown",
      message: mm ? decodeXmlEntities(mm[1]) : "",
    });
  }
  return { deleted, errors };
}

/// Base64 MD5 of a UTF-8 string (S3 DeleteObjects `Content-MD5`). Uses WebCrypto where MD5 is
/// available; workerd does NOT expose MD5 via SubtleCrypto, so we compute it in-process.
async function contentMd5(body: string): Promise<string> {
  const bytes = new TextEncoder().encode(body);
  const digest = md5Bytes(bytes);
  let bin = "";
  for (const b of digest) bin += String.fromCharCode(b);
  return btoa(bin);
}

async function safeText(res: Response): Promise<string> {
  try {
    return (await res.text()).slice(0, 200);
  } catch {
    return "";
  }
}

// ---- minimal MD5 (RFC 1321) -----------------------------------------------------------------
// workerd's SubtleCrypto has no MD5 and S3's DeleteObjects requires a Content-MD5 header. This is
// a small, dependency-free MD5 over a byte array. Only used for the (rare) batch-delete request.
function md5Bytes(input: Uint8Array): Uint8Array {
  function rotl(x: number, c: number): number {
    return (x << c) | (x >>> (32 - c));
  }
  const s = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];
  const K = new Int32Array(64);
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) | 0;

  const origLen = input.length;
  const bitLen = origLen * 8;
  // pad: append 0x80, then zeros, until length ≡ 56 (mod 64), then 8-byte little-endian bit length.
  const padded = new Uint8Array(((origLen + 8) >> 6) * 64 + 64);
  padded.set(input);
  padded[origLen] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, bitLen >>> 0, true);
  dv.setUint32(padded.length - 4, Math.floor(bitLen / 4294967296), true);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const M = new Int32Array(16);
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) M[i] = dv.getInt32(off + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F: number, g: number;
      if (i < 16) {
        F = (B & C) | (~B & D);
        g = i;
      } else if (i < 32) {
        F = (D & B) | (~D & C);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        F = B ^ C ^ D;
        g = (3 * i + 5) % 16;
      } else {
        F = C ^ (B | ~D);
        g = (7 * i) % 16;
      }
      F = (F + A + K[i] + M[g]) | 0;
      A = D;
      D = C;
      C = B;
      B = (B + rotl(F, s[i])) | 0;
    }
    a0 = (a0 + A) | 0;
    b0 = (b0 + B) | 0;
    c0 = (c0 + C) | 0;
    d0 = (d0 + D) | 0;
  }
  const out = new Uint8Array(16);
  const odv = new DataView(out.buffer);
  odv.setInt32(0, a0, true);
  odv.setInt32(4, b0, true);
  odv.setInt32(8, c0, true);
  odv.setInt32(12, d0, true);
  return out;
}
