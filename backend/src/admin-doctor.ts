// SPDX-License-Identifier: AGPL-3.0-or-later
// admin-doctor.ts — post-deploy readiness check (audit B8).
//
// `GET /v1/health` is a constant `{ok:true}` that validates nothing, so every
// misconfiguration surfaces at first use as a cryptic mount/email/passkey error.
// `GET /v1/admin/doctor` (gated by the deploy-time BOOTSTRAP_SECRET) runs the checks
// that otherwise fail silently until first use, turning ~8 "silent until first use"
// findings into ONE deploy-time signal:
//   • AUTH_SIGNING_SECRET present and ≥16 chars
//   • STORAGE_ENC_KEY decodes to 32 bytes AND round-trips a sentinel (seal→open)
//   • the DEFAULT storage backend passes the real probe (list/put/get/delete)
//   • which email provider is in effect (incl. "fake — DROPS mail")
//   • SIGNUP_MODE in effect (+ the B7 open-on-https tripwire status)
//   • any localhost-valued public URL on an https deployment
//
// Each check is { name, status: ok|warn|fail, detail }. `ok` overall iff no `fail`.

import type { Env } from "./env";
import { defaultStorageConfig } from "./storage";
import { probeStorage } from "./storage-credentials";
import { importStorageKey, sealSecret, openSecret } from "./security/storage-crypto";
import { describeSelectedEmailProvider } from "./auth-stores";
import { resolveSignupMode, shouldRefuseOpenSignupOnHttps } from "./signup-mode";
import { probeStorageIntegrity } from "./storage-object-verifier";

export type CheckStatus = "ok" | "warn" | "fail";
export interface DoctorCheck {
  name: string;
  status: CheckStatus;
  detail: string;
}
export interface DoctorReport {
  ok: boolean;
  isHttps: boolean;
  checks: DoctorCheck[];
}

/// True when the deployment is reachable over https (a real deploy, not localhost dev).
function isLocalhostUrl(u: string | undefined): boolean {
  if (!u) return false;
  try {
    const h = new URL(u).hostname;
    return h === "localhost" || h === "127.0.0.1" || h.endsWith(".local");
  } catch {
    return true; // unparseable URL is itself a problem
  }
}

/// Run the readiness checks. `isHttps` says whether the doctor was reached over https
/// (so localhost-URL checks only fail/warn on a real deployment). `storageProbe` is
/// injectable so unit tests don't hit a bucket; production passes the real one.
export async function runDoctor(
  env: Env,
  opts: {
    isHttps: boolean;
    emailProvider?: ReturnType<typeof describeSelectedEmailProvider>;
    storageProbe?: (env: Env) => Promise<{ reachable: boolean; canWrite: boolean; canRead: boolean; canDelete: boolean; error?: string }>;
    integrityProbe?: (env: Env) => Promise<{ ok: boolean }>;
  },
): Promise<DoctorReport> {
  const checks: DoctorCheck[] = [];
  const add = (name: string, status: CheckStatus, detail: string) => checks.push({ name, status, detail });

  add("upload_verification", env.STORAGE_VERIFY_UPLOADS === "0" ? "fail" : "ok",
    env.STORAGE_VERIFY_UPLOADS === "0" ? "Object verification is disabled. This is permitted only in metadata-only unit fixtures, never a deployment." : "File commits require verified object hash and size.");

  // 1. AUTH_SIGNING_SECRET ----------------------------------------------------
  if (!env.AUTH_SIGNING_SECRET) {
    add("auth_signing_secret", "fail", "AUTH_SIGNING_SECRET is not set — tokens cannot be signed. `wrangler secret put AUTH_SIGNING_SECRET`.");
  } else if (env.AUTH_SIGNING_SECRET.length < 16) {
    add("auth_signing_secret", "fail", `AUTH_SIGNING_SECRET is too short (${env.AUTH_SIGNING_SECRET.length} chars; need ≥16).`);
  } else {
    add("auth_signing_secret", "ok", "present and ≥16 chars");
  }

  // 2. STORAGE_ENC_KEY decode + round-trip ------------------------------------
  if (!env.STORAGE_ENC_KEY) {
    add("storage_enc_key", "fail", "STORAGE_ENC_KEY is not set — filespace encryption keys and managed credentials cannot be provisioned. Restore the existing key for an established deployment; never generate a replacement.");
  } else {
    try {
      await importStorageKey(env.STORAGE_ENC_KEY);
      const sealed = await sealSecret(env.STORAGE_ENC_KEY, "cloudfs-doctor-sentinel");
      const opened = await openSecret(env.STORAGE_ENC_KEY, sealed);
      if (opened === "cloudfs-doctor-sentinel") add("storage_enc_key", "ok", "decodes to 32 bytes and seal→open round-trips");
      else add("storage_enc_key", "fail", "STORAGE_ENC_KEY seal/open round-trip did not match.");
    } catch (e) {
      add("storage_enc_key", "fail", `STORAGE_ENC_KEY invalid: ${String((e as Error)?.message ?? e)}`);
    }
  }

  // 3. Default storage backend probe ------------------------------------------
  try {
    const probe = opts.storageProbe ?? defaultStorageProbe;
    const r = await probe(env);
    if (r.reachable && r.canWrite && r.canRead && r.canDelete) {
      add("default_storage_backend", "ok", `default bucket "${env.S3_BUCKET}" at ${env.S3_ENDPOINT} passed list/put/get/delete`);
    } else if (r.reachable) {
      add("default_storage_backend", "fail", `default bucket reachable but probe incomplete (write=${r.canWrite} read=${r.canRead} delete=${r.canDelete}${r.error ? `; ${r.error}` : ""})`);
    } else {
      add("default_storage_backend", "fail", `default storage backend UNREACHABLE (${r.error ?? "no detail"}) — check S3_ENDPOINT/S3_BUCKET/S3_REGION and the S3_ACCESS_KEY_ID/S3_SECRET_ACCESS_KEY secrets.`);
    }
  } catch (e) {
    add("default_storage_backend", "fail", `storage probe threw: ${String((e as Error)?.message ?? e)}`);
  }

  // Exercise all four SQLite authorities, including their schema migrations, and
  // the separate native R2 binding. A working S3 data bucket alone isn't readiness.
  const dependencies = await Promise.all([
    metadataChecks(env),
    auditBucketCheck(env),
    (async (): Promise<DoctorCheck[]> => {
      try {
        const probe = opts.integrityProbe ?? (env => probeStorageIntegrity(defaultStorageConfig(env), ".cloudfs-doctor-integrity", (input, init) => fetch(input, { ...init, signal: AbortSignal.timeout(5000), redirect: "manual" })));
        if (!(await probe(env)).ok) throw new Error("integrity_probe_failed");
        return [{ name: "storage_integrity", status: "ok", detail: "Storage rejects corrupt uploads and overwrites, and verifies uploaded checksums." }];
      } catch {
        return [{ name: "storage_integrity", status: "fail", detail: "Storage did not pass signed-checksum, conditional-write and verified-readback checks. This storage backend must support the immutable upload contract before use." }];
      }
    })(),
  ]);
  checks.push(...dependencies.flat());

  // 4. Email provider in effect -----------------------------------------------
  const email = opts.emailProvider ?? describeSelectedEmailProvider(env);
  if (email.delivers) add("email_provider", "ok", `delivering via ${email.detail}`);
  else add("email_provider", "warn", `${email.detail} — verification/reset/invite mail will NOT reach users.`);

  // 5. Signup mode ------------------------------------------------------------
  const mode = resolveSignupMode(env);
  if (shouldRefuseOpenSignupOnHttps(env, opts.isHttps)) {
    add("signup_mode", "warn", `SIGNUP_MODE=open on an https deployment WITHOUT SIGNUP_OPEN_ON_HTTPS — signup is REFUSED (fail-closed). Set SIGNUP_MODE=invite or opt in explicitly.`);
  } else {
    add("signup_mode", "ok", `effective mode: "${mode}"`);
  }

  // 6. localhost base URLs on an https deployment -----------------------------
  if (opts.isHttps) {
    const localhostUrls = [
      ["PUBLIC_BASE_URL", env.PUBLIC_BASE_URL],
      ["WEB_BASE_URL", env.WEB_BASE_URL],
      ["S3_ENDPOINT", env.S3_ENDPOINT],
    ].filter(([, v]) => isLocalhostUrl(v as string | undefined));
    if (localhostUrls.length) {
      add("public_urls", "fail", `localhost/dev value(s) on an https deployment: ${localhostUrls.map(([k, v]) => `${k}=${v}`).join(", ")} — email links/passkeys/presign will break.`);
    } else {
      add("public_urls", "ok", "no localhost-valued public URLs");
    }
    if (isLocalhostUrl(env.WEBAUTHN_RP_ID ? `https://${env.WEBAUTHN_RP_ID}` : undefined)) {
      add("webauthn_rp_id", "warn", `WEBAUTHN_RP_ID="${env.WEBAUTHN_RP_ID}" looks like a dev value — passkeys will fail on a real domain.`);
    }
  } else {
    add("public_urls", "ok", "non-https (localhost dev) — URL host check skipped");
  }

  const ok = checks.every((c) => c.status !== "fail");
  return { ok, isHttps: opts.isHttps, checks };
}

/// The real default-backend storage probe. Lists/puts/gets/deletes a sentinel object
/// under a `.cloudfs-doctor/` prefix in the deployment-default bucket.
async function defaultStorageProbe(env: Env) {
  const config = defaultStorageConfig(env);
  const r = await probeStorage(config, ".cloudfs-doctor", {
    fetch: (input, init) => fetch(input, { ...init, signal: AbortSignal.timeout(5000), redirect: "manual" }),
  });
  return { reachable: r.reachable, canWrite: r.canWrite, canRead: r.canRead, canDelete: r.canDelete, error: r.error };
}

async function metadataChecks(env: Env): Promise<DoctorCheck[]> {
  const bindings = ["DIRECTORY_DO", "ORG_DO", "AUTH_DO", "FILESPACE"] as const;
  return Promise.all(bindings.map(async binding => {
    const name = `metadata_${binding.toLowerCase()}`;
    try {
      const namespace = env[binding];
      // A reserved diagnostic instance never reads or mutates a customer's namespace.
      const report = await namespace.get(namespace.idFromName("__cloudfs_readiness__")).readiness();
      if (!Number.isSafeInteger(report.schemaVersion) || report.schemaVersion < 1) throw new Error("uninitialized_schema");
      return { name, status: "ok", detail: `SQLite ready; schema ${report.schemaVersion}, ${report.databaseBytes} bytes` };
    } catch {
      return { name, status: "fail", detail: `${binding} could not open its SQLite schema. Check the production binding, migrations and Worker logs.` };
    }
  }));
}

async function auditBucketCheck(env: Env): Promise<DoctorCheck[]> {
  const name = "audit_storage_backend";
  const key = `.cloudfs-doctor/${crypto.randomUUID()}`;
  const sentinel = crypto.randomUUID();
  try {
    if (!env.AUDIT_BUCKET) throw new Error("missing_binding");
    try {
      await env.AUDIT_BUCKET.put(key, sentinel);
      const object = await env.AUDIT_BUCKET.get(key);
      if (!object || await object.text() !== sentinel) throw new Error("readback_mismatch");
    } finally {
      // Also attempt cleanup after an ambiguous write response.
      await env.AUDIT_BUCKET.delete(key);
    }
    return [{ name, status: "ok", detail: "Audit R2 binding passed write, verified readback and delete." }];
  } catch {
    return [{ name, status: "fail", detail: "Audit R2 storage failed write/readback/delete. Check AUDIT_BUCKET; audit history must remain durable." }];
  }
}
