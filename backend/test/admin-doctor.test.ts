// SPDX-License-Identifier: AGPL-3.0-or-later
// admin-doctor.test.ts — the post-deploy readiness endpoint (audit B8).
import { SELF, env } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import { runDoctor } from "../src/admin-doctor";
import type { Env } from "../src/env";
import { mintToken, type Scope } from "../src/security/auth";

const okProbe = async () => ({ reachable: true, canWrite: true, canRead: true, canDelete: true });
const deadProbe = async () => ({ reachable: false, canWrite: false, canRead: false, canDelete: false, error: "list_failed_403" });

// A healthy-ish prod-shaped env (real secret, https URLs, delivering email, invite signup).
function healthyEnv(): Env {
  return {
    ...(env as Env),
    STORAGE_VERIFY_UPLOADS: "1",
    AUTH_SIGNING_SECRET: "a-strong-signing-secret-32-characters",
    STORAGE_ENC_KEY: (env as Env).STORAGE_ENC_KEY, // valid 32-byte key from .dev.vars
    S3_ENDPOINT: "https://acct.r2.cloudflarestorage.com",
    S3_BUCKET: "studio",
    RESEND_API_KEY: "re_test", EMAIL_FROM: "noreply@studio.example.com",
    EMAIL_DEV_CONSOLE: undefined,
    SIGNUP_MODE: "invite", SIGNUP_OPEN_ON_HTTPS: undefined,
    PUBLIC_BASE_URL: "https://gw.studio.example.com",
    WEB_BASE_URL: "https://console.studio.example.com",
    WEBAUTHN_RP_ID: "studio.example.com",
  } as unknown as Env;
}

describe("B8: runDoctor readiness checks", () => {
  it("reports ok when every prod-shaped check passes", async () => {
    const r = await runDoctor(healthyEnv(), { isHttps: true, storageProbe: okProbe, integrityProbe: async () => ({ ok: true }) });
    expect(r.ok).toBe(true);
    expect(r.checks.find((c) => c.name === "auth_signing_secret")?.status).toBe("ok");
    expect(r.checks.find((c) => c.name === "default_storage_backend")?.status).toBe("ok");
    expect(r.checks.find((c) => c.name === "email_provider")?.status).toBe("ok");
    expect(r.checks.find((c) => c.name === "signup_mode")?.status).toBe("ok");
  });

  it("FAILS when AUTH_SIGNING_SECRET is missing/short", async () => {
    const e = { ...healthyEnv(), AUTH_SIGNING_SECRET: "short" } as Env;
    const r = await runDoctor(e, { isHttps: true, storageProbe: okProbe, integrityProbe: async () => ({ ok: true }) });
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === "auth_signing_secret")?.status).toBe("fail");
  });

  it("FAILS when the default storage backend is unreachable", async () => {
    const r = await runDoctor(healthyEnv(), { isHttps: true, storageProbe: deadProbe, integrityProbe: async () => ({ ok: false }) });
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === "default_storage_backend")?.status).toBe("fail");
  });

  it("checks every metadata authority and the audit bucket", async () => {
    const r = await runDoctor(healthyEnv(), { isHttps: true, storageProbe: okProbe, integrityProbe: async () => ({ ok: true }) });
    for (const name of ["metadata_directory_do", "metadata_auth_do", "metadata_org_do", "metadata_filespace", "audit_storage_backend"]) {
      expect(r.checks.find(c => c.name === name)?.status).toBe("ok");
    }
    const remaining = await (env as Env).AUDIT_BUCKET!.list({ prefix: ".cloudfs-doctor/" });
    expect(remaining.objects).toHaveLength(0);
  });

  it("fails readiness on a broken metadata binding or missing encryption key", async () => {
    const e = { ...healthyEnv(), AUTH_DO: undefined, STORAGE_ENC_KEY: undefined } as unknown as Env;
    const r = await runDoctor(e, { isHttps: true, storageProbe: okProbe, integrityProbe: async () => ({ ok: true }) });
    expect(r.ok).toBe(false);
    expect(r.checks.find(c => c.name === "metadata_auth_do")?.status).toBe("fail");
    expect(r.checks.find(c => c.name === "storage_enc_key")?.status).toBe("fail");
  });

  it("fails readiness when audit readback is corrupt and still removes the sentinel", async () => {
    let deleted = false;
    const e = { ...healthyEnv(), AUDIT_BUCKET: {
      put: async () => ({}), get: async () => ({ text: async () => "wrong" }),
      delete: async () => { deleted = true; },
    } } as unknown as Env;
    const r = await runDoctor(e, { isHttps: true, storageProbe: okProbe, integrityProbe: async () => ({ ok: true }) });
    expect(r.ok).toBe(false);
    expect(r.checks.find(c => c.name === "audit_storage_backend")?.status).toBe("fail");
    expect(deleted).toBe(true);
  });

  it("WARNS (not delivering) when no email provider is configured — mail is silently dropped", async () => {
    const e = { ...healthyEnv(), RESEND_API_KEY: undefined } as Env;
    const r = await runDoctor(e, { isHttps: true, storageProbe: okProbe, integrityProbe: async () => ({ ok: true }) });
    const email = r.checks.find((c) => c.name === "email_provider");
    expect(email?.status).toBe("warn");
    expect(email?.detail).toMatch(/DROPPED|no-op fake/i);
  });

  it("reports the configured production Cloudflare binding as the effective provider", async () => {
    const e = {
      ...healthyEnv(),
      EMAIL_PROVIDER: "cloudflare",
      EMAIL_FROM: "noreply@example.com",
      RESEND_API_KEY: undefined,
      EMAIL: { send: async () => ({ messageId: "cf-message-1" }) },
    } as unknown as Env;
    const r = await runDoctor(e, { isHttps: true, storageProbe: okProbe, integrityProbe: async () => ({ ok: true }) });
    expect(r.checks.find((c) => c.name === "email_provider")).toMatchObject({
      status: "ok",
      detail: expect.stringContaining("Cloudflare Email Sending"),
    });
  });

  it("uses an org runtime-provider description when supplied by the owner doctor", async () => {
    const r = await runDoctor(healthyEnv(), {
      isHttps: true,
      storageProbe: okProbe,
      integrityProbe: async () => ({ ok: true }),
      emailProvider: { provider: "cloudflare", delivers: true, detail: "Cloudflare Email Sending (org override)" },
    });
    expect(r.checks.find((c) => c.name === "email_provider")).toMatchObject({
      status: "ok",
      detail: expect.stringContaining("org override"),
    });
  });

  it("FAILS on a localhost base URL on an https deployment (the deploy-the-dev-config trap)", async () => {
    const e = { ...healthyEnv(), PUBLIC_BASE_URL: "http://localhost:8787" } as Env;
    const r = await runDoctor(e, { isHttps: true, storageProbe: okProbe, integrityProbe: async () => ({ ok: true }) });
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === "public_urls")?.status).toBe("fail");
  });

  it("WARNS when SIGNUP_MODE=open on https without the opt-in (B7 tripwire surfaced)", async () => {
    const e = { ...healthyEnv(), SIGNUP_MODE: "open" } as Env;
    const r = await runDoctor(e, { isHttps: true, storageProbe: okProbe, integrityProbe: async () => ({ ok: true }) });
    expect(r.checks.find((c) => c.name === "signup_mode")?.status).toBe("warn");
  });
});

describe("B8: GET /v1/admin/doctor route (BOOTSTRAP_SECRET-gated)", () => {
  it("401s without the bootstrap secret, serves the report with it", async () => {
    const noAuth = await SELF.fetch("https://gw.local/v1/admin/doctor");
    expect(noAuth.status).toBe(401);

    const secret = (env as Env).BOOTSTRAP_SECRET!;
    const res = await SELF.fetch("https://gw.local/v1/admin/doctor", {
      headers: { "x-bootstrap-secret": secret },
    });
    // The dev env (localhost URLs, MinIO) will report some warns/fails — what matters
    // is the route authenticates and returns a structured report.
    const body = (await res.json()) as { ok: boolean; checks: { name: string }[] };
    expect(Array.isArray(body.checks)).toBe(true);
    expect(body.checks.map((c) => c.name)).toContain("auth_signing_secret");
    expect([200, 503]).toContain(res.status);
  });
});

describe("ONBOARDING.md build step 5: GET /v1/orgs/:org/doctor (owner/admin session-gated)", () => {
  // Reachable from an already-signed-in wizard/console session, unlike the BOOTSTRAP_SECRET-gated
  // /v1/admin/doctor above — the setup wizard's health-check step runs AFTER the secret was
  // already spent (and cleared from page memory) creating the org + admin.
  const ORG = "doctor-wizard-org";
  const ALL_SCOPES: Scope[] = ["fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write", "audit:read"];
  const SECRET = (env as Env).AUTH_SIGNING_SECRET as string;
  let ownerAuth: Record<string, string>;
  let standardAuth: Record<string, string>;

  beforeAll(async () => {
    const boot = await SELF.fetch("https://gw.local/v1/bootstrap", {
      method: "POST",
      headers: { "content-type": "application/json", "x-bootstrap-secret": (env as Env).BOOTSTRAP_SECRET! },
      body: JSON.stringify({ orgId: ORG, email: `owner@${ORG}.test`, displayName: "Owner", allowTokenOnly: true }),
    });
    const { token: ownerToken } = (await boot.json()) as { token: string; userId: string };
    ownerAuth = { Authorization: `Bearer ${ownerToken}` };

    const org = (env as any).ORG_DO.getByName(ORG);
    const std = await org.createUser({ orgId: ORG, email: `std-${crypto.randomUUID()}@${ORG}.test`, displayName: "Std", role: "standard" });
    const stdToken = await mintToken(SECRET, { sub: std.id, type: "session", orgId: ORG, scopes: ALL_SCOPES, ttlSeconds: 900 });
    standardAuth = { Authorization: `Bearer ${stdToken}` };
  });

  it("403s a non-admin member", async () => {
    const res = await SELF.fetch(`https://gw.local/v1/orgs/${ORG}/doctor`, { headers: standardAuth });
    expect(res.status).toBe(403);
  });

  it("401s with no credential at all (the ordinary bearer gate, not the doctor route itself)", async () => {
    const res = await SELF.fetch(`https://gw.local/v1/orgs/${ORG}/doctor`);
    expect(res.status).toBe(401);
  });

  it("200s an owner/admin with the SAME structured report shape as the bootstrap-gated route", async () => {
    const res = await SELF.fetch(`https://gw.local/v1/orgs/${ORG}/doctor`, { headers: ownerAuth });
    // Always 200 here (never 503) — an interactive wizard reads the body, not the status.
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; isHttps: boolean; checks: { name: string; status: string }[] };
    expect(Array.isArray(body.checks)).toBe(true);
    expect(body.checks.map((c) => c.name)).toEqual(
      expect.arrayContaining(["email_provider", "storage_enc_key", "public_urls"]),
    );
  });

  it("only GET is allowed", async () => {
    const res = await SELF.fetch(`https://gw.local/v1/orgs/${ORG}/doctor`, { method: "POST", headers: ownerAuth });
    expect(res.status).toBe(405);
  });
});
