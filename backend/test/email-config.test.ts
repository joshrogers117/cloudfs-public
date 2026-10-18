// SPDX-License-Identifier: AGPL-3.0-or-later
// email-config.test.ts — UI-managed, encrypted-at-rest per-org email-provider config + test-send
// (email-config.ts + security/storage-crypto.ts). Unit-level: the HTTP handler over an in-memory
// OrgStub, plus the runtime-vs-env resolution and the test-send with an INJECTED sender (no net).
//
// Covers:
//   1. CRUD via the handler: GET null when unset; PUT seals the secret + returns the SAFE shape;
//      GET returns the saved config; DELETE 204 reverts to null.
//   2. secret-never-leaks: no response body (PUT/GET) ever contains the plaintext secret; the
//      stored row keeps it AES-256-GCM encrypted (iv/ct), and seal→open round-trips.
//   3. runtime-overrides-env: `emailSenderForOrg`-style resolution builds the RUNTIME sender from
//      the saved config FIRST; with no saved config it falls back to the env path.
//   4. test-send: builds a sender from SAVED config OR unsaved body creds; maps a thrown send to
//      `{ sent:false, error }` (never throws); the injected sender records the "cloud-fs test email".
//   5. role gating: a non-admin caller is 403 on every email-config route.

import { describe, it, expect } from "vitest";
import {
  handleEmailConfigRequest,
  buildRuntimeSender,
  describeRuntimeEmailProvider,
  runtimeEmailSenderFor,
  resolveStoredConfig,
  toPublicEmailConfig,
  type EmailConfigOrgStub,
  type ResolvedEmailConfig,
  type EmailConfig,
} from "../src/email-config";
import { sealSecret, openSecret } from "../src/security/storage-crypto";
import { FakeEmailSender, type EmailSender, type SendEmailBinding } from "../src/security/auth-email";
import type { AuthedContext, EmailConfigRow } from "../src/org-do";
import type { Env } from "../src/env";

const ENC_KEY = "qbQu5yxLGHtdYKJ6z84mem+Mn5vo5PdUJvawJ0T6D8E="; // 32 bytes base64 (test-only)

function envWith(over: Record<string, unknown> = {}): Env {
  return { STORAGE_ENC_KEY: ENC_KEY, ...over } as unknown as Env;
}

// ---- in-memory OrgStub (the slice email-config.ts needs) -------------------------------
function makeOrgStub(): EmailConfigOrgStub & { _row: EmailConfigRow | null } {
  const state: { row: EmailConfigRow | null } = { row: null };
  return {
    get _row() {
      return state.row;
    },
    async getEmailConfig() {
      return state.row;
    },
    async putEmailConfig(input) {
      const now = Date.now();
      state.row = {
        orgId: input.orgId,
        provider: input.provider,
        fromAddress: input.fromAddress,
        fromName: input.fromName,
        region: input.region,
        secretIv: input.secretIv,
        secretCiphertext: input.secretCiphertext,
        sesAccessKeyId: input.sesAccessKeyId,
        createdAt: state.row?.createdAt ?? now,
        updatedAt: now,
      };
      return state.row;
    },
    async deleteEmailConfig() {
      const had = state.row !== null;
      state.row = null;
      return had;
    },
  };
}

const ADMIN: AuthedContext = { principalUserId: "usr-admin", orgRole: "admin" };
const OWNER: AuthedContext = { principalUserId: "usr-owner", orgRole: "owner" };
const STANDARD: AuthedContext = { principalUserId: "usr-std", orgRole: "standard" };

function req(method: string, path = "email-config", body?: unknown): Request {
  return new Request(`https://gw.local/v1/orgs/org1/${path}`, {
    method,
    headers: { "content-type": "application/json" },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
}

const RESEND_SECRET = "re_test_SUPERSECRET_resend_key";

describe("email-config CRUD (handler over in-memory OrgStub)", () => {
  it("GET returns { config: null } when nothing is saved", async () => {
    const org = makeOrgStub();
    const res = await handleEmailConfigRequest(req("GET"), envWith(), OWNER, ["email-config"], "org1", { org });
    expect(res!.status).toBe(200);
    expect(await res!.json()).toEqual({ config: null });
  });

  it("PUT seals the secret, returns the SAFE shape, and the secret is never echoed", async () => {
    const org = makeOrgStub();
    const res = await handleEmailConfigRequest(
      req("PUT", "email-config", { provider: "resend", fromAddress: "no-reply@acme.test", fromName: "Acme", secret: RESEND_SECRET }),
      envWith(),
      OWNER,
      ["email-config"],
      "org1",
      { org },
    );
    expect(res!.status).toBe(200);
    const text = await res!.clone().text();
    expect(text).not.toContain(RESEND_SECRET);
    const cfg = (await res!.json()) as EmailConfig;
    expect(cfg).toEqual({ provider: "resend", fromAddress: "no-reply@acme.test", fromName: "Acme", configured: true });

    // The stored row keeps the secret ENCRYPTED, and it round-trips via open().
    const row = org._row!;
    expect(row.secretCiphertext).not.toBe("");
    expect(JSON.stringify(row)).not.toContain(RESEND_SECRET);
    expect(await openSecret(ENC_KEY, { iv: row.secretIv, ciphertext: row.secretCiphertext })).toBe(RESEND_SECRET);

    // GET now returns the safe config (still no secret).
    const got = await handleEmailConfigRequest(req("GET"), envWith(), OWNER, ["email-config"], "org1", { org });
    const gotText = await got!.clone().text();
    expect(gotText).not.toContain(RESEND_SECRET);
    expect((await got!.json()) as { config: EmailConfig }).toEqual({
      config: { provider: "resend", fromAddress: "no-reply@acme.test", fromName: "Acme", configured: true },
    });
  });

  it("PUT can edit the from name without resending the secret (secret retained)", async () => {
    const org = makeOrgStub();
    await handleEmailConfigRequest(
      req("PUT", "email-config", { provider: "resend", fromAddress: "a@acme.test", secret: RESEND_SECRET }),
      envWith(), OWNER, ["email-config"], "org1", { org },
    );
    const before = org._row!;
    // Edit just the from name; omit the secret.
    const res = await handleEmailConfigRequest(
      req("PUT", "email-config", { provider: "resend", fromAddress: "a@acme.test", fromName: "Renamed" }),
      envWith(), OWNER, ["email-config"], "org1", { org },
    );
    expect(res!.status).toBe(200);
    const row = org._row!;
    expect(row.fromName).toBe("Renamed");
    // Same sealed envelope retained.
    expect(row.secretCiphertext).toBe(before.secretCiphertext);
    expect(await openSecret(ENC_KEY, { iv: row.secretIv, ciphertext: row.secretCiphertext })).toBe(RESEND_SECRET);
  });

  it("PUT cloudflare needs no secret; SES requires region + accessKeyId + secret", async () => {
    const org = makeOrgStub();
    const cf = await handleEmailConfigRequest(
      req("PUT", "email-config", { provider: "cloudflare", fromAddress: "cf@acme.test" }),
      envWith(), OWNER, ["email-config"], "org1", { org },
    );
    expect(cf!.status).toBe(200);
    expect(org._row!.secretCiphertext).toBe(""); // no secret sealed for cloudflare

    const sesBad = await handleEmailConfigRequest(
      req("PUT", "email-config", { provider: "ses", fromAddress: "s@acme.test", sesAccessKeyId: "AKID" }),
      envWith(), OWNER, ["email-config"], "org1", { org },
    );
    expect(sesBad!.status).toBe(400); // missing sesRegion + sesSecretAccessKey

    const sesOk = await handleEmailConfigRequest(
      req("PUT", "email-config", { provider: "ses", fromAddress: "s@acme.test", sesAccessKeyId: "AKID", sesSecretAccessKey: "SECRET", sesRegion: "us-east-1" }),
      envWith(), OWNER, ["email-config"], "org1", { org },
    );
    expect(sesOk!.status).toBe(200);
    const cfg = (await sesOk!.json()) as EmailConfig;
    expect(cfg).toEqual({ provider: "ses", fromAddress: "s@acme.test", region: "us-east-1", configured: true });
    expect(org._row!.sesAccessKeyId).toBe("AKID");
    expect(await openSecret(ENC_KEY, { iv: org._row!.secretIv, ciphertext: org._row!.secretCiphertext })).toBe("SECRET");
  });

  it("PUT with a bad provider → 400; missing fromAddress → 400", async () => {
    const org = makeOrgStub();
    const bad = await handleEmailConfigRequest(
      req("PUT", "email-config", { provider: "mailgun", fromAddress: "x@y.test", secret: "k" }),
      envWith(), OWNER, ["email-config"], "org1", { org },
    );
    expect(bad!.status).toBe(400);
    const noFrom = await handleEmailConfigRequest(
      req("PUT", "email-config", { provider: "resend", secret: "k" }),
      envWith(), OWNER, ["email-config"], "org1", { org },
    );
    expect(noFrom!.status).toBe(400);
  });

  it("DELETE reverts to null (204)", async () => {
    const org = makeOrgStub();
    await handleEmailConfigRequest(
      req("PUT", "email-config", { provider: "resend", fromAddress: "a@acme.test", secret: RESEND_SECRET }),
      envWith(), OWNER, ["email-config"], "org1", { org },
    );
    const del = await handleEmailConfigRequest(req("DELETE"), envWith(), OWNER, ["email-config"], "org1", { org });
    expect(del!.status).toBe(204);
    const got = await handleEmailConfigRequest(req("GET"), envWith(), OWNER, ["email-config"], "org1", { org });
    expect(await got!.json()).toEqual({ config: null });
  });

  it("PUT fails closed (500 storage_enc_key_unconfigured) when STORAGE_ENC_KEY is unset", async () => {
    const org = makeOrgStub();
    const res = await handleEmailConfigRequest(
      req("PUT", "email-config", { provider: "resend", fromAddress: "a@acme.test", secret: RESEND_SECRET }),
      envWith({ STORAGE_ENC_KEY: undefined }),
      OWNER, ["email-config"], "org1", { org },
    );
    expect(res!.status).toBe(500);
    expect((await res!.json()) as { error: string }).toMatchObject({ error: "storage_enc_key_unconfigured" });
  });
});

describe("email-config role gating", () => {
  for (const method of ["GET", "PUT", "DELETE"] as const) {
    it(`a standard (non-admin) member is 403 on ${method}`, async () => {
      const org = makeOrgStub();
      const body = method === "PUT" ? { provider: "resend", fromAddress: "a@acme.test", secret: "k" } : undefined;
      const res = await handleEmailConfigRequest(req(method, "email-config", body), envWith(), STANDARD, ["email-config"], "org1", { org });
      expect(res!.status).toBe(403);
    });
  }
  it("a standard member is 403 on /email-config/test", async () => {
    const org = makeOrgStub();
    const res = await handleEmailConfigRequest(
      req("POST", "email-config/test", { to: "x@y.test" }),
      envWith(), STANDARD, ["email-config", "test"], "org1", { org },
    );
    expect(res!.status).toBe(403);
  });
  it("both owner and admin are allowed (GET 200)", async () => {
    const org = makeOrgStub();
    for (const ctx of [OWNER, ADMIN]) {
      const res = await handleEmailConfigRequest(req("GET"), envWith(), ctx, ["email-config"], "org1", { org });
      expect(res!.status).toBe(200);
    }
  });
});

describe("runtime-overrides-env resolution", () => {
  it("buildRuntimeSender builds a real provider sender from a resolved config", () => {
    const cfg: ResolvedEmailConfig = { provider: "resend", fromAddress: "a@acme.test", secret: RESEND_SECRET };
    expect(buildRuntimeSender(cfg)).not.toBeNull();
    // Cloudflare needs the binding; without one it can't build (→ caller falls back to env).
    expect(buildRuntimeSender({ provider: "cloudflare", fromAddress: "a@acme.test" })).toBeNull();
    // Resend without a secret can't build.
    expect(buildRuntimeSender({ provider: "resend", fromAddress: "a@acme.test" })).toBeNull();
  });

  it("runtimeEmailSenderFor returns a sender when a config is saved, null when absent", async () => {
    const org = makeOrgStub();
    // No row → null (caller uses env).
    expect(await runtimeEmailSenderFor(envWith(), org)).toBeNull();
    // Save a Resend config → a runtime sender is built (RUNTIME wins over env).
    const sealed = await sealSecret(ENC_KEY, RESEND_SECRET);
    await org.putEmailConfig({
      orgId: "org1", provider: "resend", fromAddress: "a@acme.test", fromName: null, region: null,
      secretIv: sealed.iv, secretCiphertext: sealed.ciphertext, sesAccessKeyId: null,
    });
    const sender = await runtimeEmailSenderFor(envWith(), org);
    expect(sender).not.toBeNull();
  });

  it("describes a buildable per-org Cloudflare override for the admin doctor", async () => {
    const org = makeOrgStub();
    const EMAIL: SendEmailBinding = { send: async () => ({ messageId: "cf-message-1" }) };
    await org.putEmailConfig({
      orgId: "org1", provider: "cloudflare", fromAddress: "noreply@example.com", fromName: "CloudFS",
      region: null, secretIv: "", secretCiphertext: "", sesAccessKeyId: null,
    });

    await expect(describeRuntimeEmailProvider(envWith({ EMAIL }), org)).resolves.toMatchObject({
      provider: "cloudflare", delivers: true, detail: "Cloudflare Email Sending (org override)",
    });
  });

  it("runtimeEmailSenderFor returns null (→ env fallback) when the secret can't be decrypted", async () => {
    const org = makeOrgStub();
    await org.putEmailConfig({
      orgId: "org1", provider: "resend", fromAddress: "a@acme.test", fromName: null, region: null,
      secretIv: "AAAAAAAAAAAAAAAA", secretCiphertext: "bm90LXJlYWwtY2lwaGVydGV4dA==", sesAccessKeyId: null,
    });
    // Wrong key (or tampered ct) → openSecret throws → resolver swallows → null.
    expect(await runtimeEmailSenderFor(envWith(), org)).toBeNull();
  });

  it("resolveStoredConfig decrypts the secret for server-side use only", async () => {
    const sealed = await sealSecret(ENC_KEY, RESEND_SECRET);
    const row: EmailConfigRow = {
      orgId: "org1", provider: "resend", fromAddress: "a@acme.test", fromName: "Acme", region: null,
      secretIv: sealed.iv, secretCiphertext: sealed.ciphertext, sesAccessKeyId: null,
      createdAt: 1, updatedAt: 1,
    };
    const cfg = await resolveStoredConfig(envWith(), row);
    expect(cfg.secret).toBe(RESEND_SECRET);
    // The PUBLIC projection never carries the secret.
    expect(JSON.stringify(toPublicEmailConfig(row))).not.toContain(RESEND_SECRET);
  });
});

describe("email-config test-send (injected sender; never throws)", () => {
  function depsWithFake(org: EmailConfigOrgStub, fake: FakeEmailSender) {
    return {
      org,
      buildSender: (_cfg: ResolvedEmailConfig): EmailSender | null => fake,
    };
  }

  it("sends a 'cloud-fs test email' via UNSAVED body creds (works before saving)", async () => {
    const org = makeOrgStub();
    const fake = new FakeEmailSender();
    const res = await handleEmailConfigRequest(
      req("POST", "email-config/test", { to: "dest@acme.test", provider: "resend", fromAddress: "a@acme.test", secret: RESEND_SECRET }),
      envWith(), OWNER, ["email-config", "test"], "org1", depsWithFake(org, fake),
    );
    expect(res!.status).toBe(200);
    expect(await res!.json()).toEqual({ sent: true });
    expect(fake.last?.to).toBe("dest@acme.test");
    expect(fake.last?.subject).toBe("cloud-fs test email");
    // Nothing was persisted (test before save).
    expect(org._row).toBeNull();
  });

  it("sends via the SAVED config when the body carries only { to }", async () => {
    const org = makeOrgStub();
    const fake = new FakeEmailSender();
    await handleEmailConfigRequest(
      req("PUT", "email-config", { provider: "resend", fromAddress: "a@acme.test", secret: RESEND_SECRET }),
      envWith(), OWNER, ["email-config"], "org1", { org },
    );
    const res = await handleEmailConfigRequest(
      req("POST", "email-config/test", { to: "dest@acme.test" }),
      envWith(), OWNER, ["email-config", "test"], "org1", depsWithFake(org, fake),
    );
    expect(res!.status).toBe(200);
    expect(await res!.json()).toEqual({ sent: true });
    expect(fake.last?.to).toBe("dest@acme.test");
  });

  it("maps a provider send failure to { sent:false, error } (never throws)", async () => {
    const org = makeOrgStub();
    const fake = new FakeEmailSender();
    fake.failNext = new Error("resend send failed: 401 unauthorized");
    const res = await handleEmailConfigRequest(
      req("POST", "email-config/test", { to: "dest@acme.test", provider: "resend", fromAddress: "a@acme.test", secret: "bad" }),
      envWith(), OWNER, ["email-config", "test"], "org1", depsWithFake(org, fake),
    );
    expect(res!.status).toBe(200);
    const body = (await res!.json()) as { sent: boolean; error?: string };
    expect(body.sent).toBe(false);
    expect(body.error).toContain("resend send failed");
  });

  it("returns { sent:false, error:'no_email_config' } with no saved config and no body creds", async () => {
    const org = makeOrgStub();
    const fake = new FakeEmailSender();
    const res = await handleEmailConfigRequest(
      req("POST", "email-config/test", { to: "dest@acme.test" }),
      envWith(), OWNER, ["email-config", "test"], "org1", depsWithFake(org, fake),
    );
    expect(res!.status).toBe(200);
    expect((await res!.json()) as { sent: boolean; error?: string }).toEqual({ sent: false, error: "no_email_config" });
  });

  it("requires `to` (→ { sent:false })", async () => {
    const org = makeOrgStub();
    const res = await handleEmailConfigRequest(
      req("POST", "email-config/test", { provider: "resend", fromAddress: "a@acme.test", secret: RESEND_SECRET }),
      envWith(), OWNER, ["email-config", "test"], "org1", { org },
    );
    expect(res!.status).toBe(200);
    expect((await res!.json()) as { sent: boolean }).toMatchObject({ sent: false });
  });
});

describe("handler scoping", () => {
  it("returns null for a non-email-config path (so the gateway tries other handlers)", async () => {
    const org = makeOrgStub();
    const res = await handleEmailConfigRequest(req("GET", "invites"), envWith(), OWNER, ["invites"], "org1", { org });
    expect(res).toBeNull();
  });
});
