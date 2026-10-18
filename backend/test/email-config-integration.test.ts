// SPDX-License-Identifier: AGPL-3.0-or-later
// email-config-integration.test.ts — end-to-end through the gateway (SELF.fetch): the
// /v1/orgs/:org/email-config CRUD routes + /email-config/test against a REAL OrgDO, the role
// gate, and the secret-never-leaks guarantee persisted across DO reads.
//
// Bootstrap mints an owner token; a second provisioned standard user proves the 403 gate.

import { SELF, env } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import { mintToken, type Scope } from "../src/security/auth";

const ALL_SCOPES: Scope[] = ["fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write", "audit:read"];
const BOOT_SECRET = "local-dev-bootstrap-secret-change-me-32chars";

async function bootstrap(orgId: string): Promise<{ token: string; userId: string }> {
  const res = await SELF.fetch("https://gw.local/v1/bootstrap", {
    method: "POST",
    headers: { "content-type": "application/json", "x-bootstrap-secret": BOOT_SECRET },
    // allowTokenOnly: token-only seeding (no admin password) is now an explicit opt-in (auth-spec §2.5).
    body: JSON.stringify({ orgId, email: `owner@${orgId}.test`, displayName: "Owner", allowTokenOnly: true }),
  });
  const b = (await res.json()) as { token: string; userId: string };
  return b;
}

async function standardToken(orgId: string): Promise<string> {
  const org = (env as any).ORG_DO.getByName(orgId);
  const u = await org.createUser({ orgId, email: `std-${crypto.randomUUID()}@${orgId}.test`, displayName: "Std", role: "standard" });
  return mintToken((env as any).AUTH_SIGNING_SECRET, { sub: u.id, type: "session", orgId, scopes: ALL_SCOPES, ttlSeconds: 900 });
}

const ORG = "email-cfg-org";
let ownerAuth: Record<string, string>;
let stdAuth: Record<string, string>;
const BASE = `https://gw.local/v1/orgs/${ORG}`;
const RESEND_SECRET = "re_int_SUPERSECRET_resend_key";

beforeAll(async () => {
  const boot = await bootstrap(ORG);
  ownerAuth = { Authorization: `Bearer ${boot.token}`, "content-type": "application/json" };
  stdAuth = { Authorization: `Bearer ${await standardToken(ORG)}`, "content-type": "application/json" };
});

describe("email-config CRUD (end-to-end, real OrgDO)", () => {
  it("GET is null initially; PUT saves; GET returns the safe config; DELETE reverts — secret never leaks", async () => {
    // initially null (using deploy env / default)
    const init = await SELF.fetch(`${BASE}/email-config`, { headers: ownerAuth });
    expect(init.status).toBe(200);
    expect(await init.json()).toEqual({ config: null });

    // PUT a Resend config
    const put = await SELF.fetch(`${BASE}/email-config`, {
      method: "PUT", headers: ownerAuth,
      body: JSON.stringify({ provider: "resend", fromAddress: "no-reply@acme.test", fromName: "Acme", secret: RESEND_SECRET }),
    });
    expect(put.status).toBe(200);
    const putText = await put.clone().text();
    expect(putText).not.toContain(RESEND_SECRET);
    expect(await put.json()).toEqual({ provider: "resend", fromAddress: "no-reply@acme.test", fromName: "Acme", configured: true });

    // GET returns the saved config across a fresh DO read — and STILL no secret
    const got = await SELF.fetch(`${BASE}/email-config`, { headers: ownerAuth });
    const gotText = await got.clone().text();
    expect(gotText).not.toContain(RESEND_SECRET);
    expect(await got.json()).toEqual({ config: { provider: "resend", fromAddress: "no-reply@acme.test", fromName: "Acme", configured: true } });

    // DELETE reverts to null
    const del = await SELF.fetch(`${BASE}/email-config`, { method: "DELETE", headers: ownerAuth });
    expect(del.status).toBe(204);
    const after = await SELF.fetch(`${BASE}/email-config`, { headers: ownerAuth });
    expect(await after.json()).toEqual({ config: null });
  });

  it("a standard (non-admin) member is 403 on GET / PUT / DELETE / test", async () => {
    const get = await SELF.fetch(`${BASE}/email-config`, { headers: stdAuth });
    expect(get.status).toBe(403);
    const put = await SELF.fetch(`${BASE}/email-config`, {
      method: "PUT", headers: stdAuth,
      body: JSON.stringify({ provider: "resend", fromAddress: "x@y.test", secret: "k" }),
    });
    expect(put.status).toBe(403);
    const del = await SELF.fetch(`${BASE}/email-config`, { method: "DELETE", headers: stdAuth });
    expect(del.status).toBe(403);
    const test = await SELF.fetch(`${BASE}/email-config/test`, { method: "POST", headers: stdAuth, body: JSON.stringify({ to: "x@y.test" }) });
    expect(test.status).toBe(403);
  });

  it("PUT with a bad provider → 400; test-send with no `to` → { sent:false }", async () => {
    const bad = await SELF.fetch(`${BASE}/email-config`, {
      method: "PUT", headers: ownerAuth,
      body: JSON.stringify({ provider: "mailgun", fromAddress: "x@y.test", secret: "k" }),
    });
    expect(bad.status).toBe(400);

    const noTo = await SELF.fetch(`${BASE}/email-config/test`, { method: "POST", headers: ownerAuth, body: JSON.stringify({}) });
    expect(noTo.status).toBe(200);
    expect((await noTo.json()) as { sent: boolean }).toMatchObject({ sent: false });
  });

  it("test-send never throws — an unreachable provider maps to { sent:false, error }", async () => {
    // Body creds for a Resend send pointed at the real API with a bogus key: the request leaves
    // (or fails) and is mapped to a structured failure, NOT a 5xx. (No network in the test env →
    // a fetch error is still mapped to sent:false.)
    const res = await SELF.fetch(`${BASE}/email-config/test`, {
      method: "POST", headers: ownerAuth,
      body: JSON.stringify({ to: "dest@acme.test", provider: "resend", fromAddress: "a@acme.test", secret: "re_bogus_key" }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { sent: boolean; error?: string };
    expect(body.sent).toBe(false);
    expect(typeof body.error).toBe("string");
  });
});
