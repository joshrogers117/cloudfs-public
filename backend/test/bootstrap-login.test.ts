// SPDX-License-Identifier: AGPL-3.0-or-later
// bootstrap-login.test.ts — audit B10: bootstrap → an actual login.
//
// POST /v1/bootstrap used to create ONLY an OrgDO user + a 15-min token but NO AuthDO
// account/credential, so the documented first-org admin got `invalid_credentials` at the
// console once the token lapsed. With a `password` in the body, bootstrap now creates a
// FULL (email-pre-verified) AuthDO account so the admin can sign in.
import { SELF, env } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";

import { resetSetupFixture } from "./setup-fixture";
beforeEach(resetSetupFixture);

const BOOT_SECRET = (env as any).BOOTSTRAP_SECRET as string;
const ORIGIN = "https://gw.local";

async function bootstrap(orgId: string, body: Record<string, unknown>) {
  return SELF.fetch(`${ORIGIN}/v1/bootstrap`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-bootstrap-secret": BOOT_SECRET },
    body: JSON.stringify({ orgId, ...body }),
  });
}

describe("B10: bootstrap with a password creates a sign-in-able admin", () => {
  it("the bootstrapped owner can log in with the chosen password", async () => {
    const orgId = `org-boot-${crypto.randomUUID().slice(0, 8)}`;
    const email = `owner@${orgId}.test`;
    const password = "correct horse battery staple";

    const boot = await bootstrap(orgId, { email, displayName: "Owner", password });
    expect(boot.status).toBe(201);
    const body = (await boot.json()) as { credentialed: boolean; token: string; userId: string };
    expect(body.credentialed).toBe(true); // a full AuthDO account was created

    // The documented failure: pre-fix this 401'd with invalid_credentials. Now it works.
    const login = await SELF.fetch(`${ORIGIN}/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    expect(login.status).toBe(200);
    const cookie = login.headers.get("set-cookie") ?? "";
    expect(cookie).toContain("cfs_session=");
  });

  it("a wrong password is rejected (the credential is real, not a stub)", async () => {
    const orgId = `org-boot2-${crypto.randomUUID().slice(0, 8)}`;
    const email = `owner@${orgId}.test`;
    expect((await bootstrap(orgId, { email, password: "the real password 123" })).status).toBe(201);
    const login = await SELF.fetch(`${ORIGIN}/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: "wrong password" }),
    });
    expect(login.status).toBe(401);
  });

  it("bootstrap WITHOUT a password is now refused (400 password_required) — decision D", async () => {
    const orgId = `org-boot3-${crypto.randomUUID().slice(0, 8)}`;
    const boot = await bootstrap(orgId, { email: `owner@${orgId}.test`, displayName: "Owner" });
    expect(boot.status).toBe(400);
    expect(((await boot.json()) as { error: string }).error).toBe("password_required");
    // …and nothing was half-created: an allowTokenOnly retry on the SAME org succeeds (not 409).
    const retry = await bootstrap(orgId, { email: `owner@${orgId}.test`, displayName: "Owner", allowTokenOnly: true });
    expect(retry.status).toBe(201);
  });

  it("allowTokenOnly:true is the explicit automation escape hatch (credentialed:false)", async () => {
    const orgId = `org-boot5-${crypto.randomUUID().slice(0, 8)}`;
    const boot = await bootstrap(orgId, { email: `owner@${orgId}.test`, displayName: "Owner", allowTokenOnly: true });
    expect(boot.status).toBe(201);
    expect(((await boot.json()) as { credentialed: boolean }).credentialed).toBe(false);
  });

  it("a too-short password is rejected (400), nothing half-created blocks a retry", async () => {
    const orgId = `org-boot4-${crypto.randomUUID().slice(0, 8)}`;
    const email = `owner@${orgId}.test`;
    const weak = await bootstrap(orgId, { email, password: "short" });
    expect(weak.status).toBe(400);
  });
});
