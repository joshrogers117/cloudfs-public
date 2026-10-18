// SPDX-License-Identifier: AGPL-3.0-or-later
// setup-wizard.test.ts — the first-run setup surface (auth-spec §2.5): GET /v1/setup/status +
// POST /v1/setup/init, end-to-end through the real worker. The happy path (init → signed-in
// cookie → self-disable) is ONE test so it never depends on cross-test storage semantics; the
// legacy-bootstrap flag flip lives in setup-bootstrap-flag.test.ts (a completed setup in this
// file would mask it).

import { SELF, env } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import { __resetSetupStatusCacheForTest } from "../src/setup";

const ORIGIN = "https://gw.local";
const BOOT_SECRET = (env as any).BOOTSTRAP_SECRET as string;

let ipCounter = 0;
function jsonHeaders(): Record<string, string> {
  ipCounter++;
  return { "content-type": "application/json", "cf-connecting-ip": `192.0.2.${ipCounter % 255}` };
}

async function status(): Promise<{ res: Response; body: any }> {
  const res = await SELF.fetch(`${ORIGIN}/v1/setup/status`);
  return { res, body: await res.json() };
}

async function init(body: Record<string, unknown>): Promise<Response> {
  return SELF.fetch(`${ORIGIN}/v1/setup/init`, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify(body),
  });
}

function validBody(orgId: string): Record<string, unknown> {
  return {
    secret: BOOT_SECRET,
    orgId,
    orgName: "Acme Post",
    email: `admin@${orgId}.example`,
    displayName: "Josh",
    password: "correct horse battery staple",
  };
}

// The per-isolate status cache must never leak a stale answer across tests (the durable flag
// is reset by the pool's storage isolation; the module cache is not).
beforeEach(() => __resetSetupStatusCacheForTest());

describe("GET /v1/setup/status", () => {
  it("a fresh deployment reports { needed: true } and nothing else", async () => {
    const { res, body } = await status();
    expect(res.status).toBe(200);
    expect(body).toEqual({ needed: true });
  });

  it("only GET is served (POST → 405)", async () => {
    const res = await SELF.fetch(`${ORIGIN}/v1/setup/status`, { method: "POST", headers: jsonHeaders() });
    expect(res.status).toBe(405);
  });
});

describe("POST /v1/setup/init — validation + gates (none of these complete setup)", () => {
  it("a wrong secret is 401 unauthorized (constant-time gate)", async () => {
    const res = await init({ ...validBody("acme-w"), secret: "wrong-secret-but-long-enough-123" });
    expect(res.status).toBe(401);
    expect(((await res.json()) as any).error).toBe("unauthorized");
  });

  it("a missing/short password is 400 weak_password", async () => {
    for (const password of [undefined, "short"]) {
      const res = await init({ ...validBody("acme-pw"), password });
      expect(res.status).toBe(400);
      expect(((await res.json()) as any).error).toBe("weak_password");
    }
  });

  it("a malformed orgId is 400 invalid_body — dots/uppercase/empty are refused (org-qualified handles)", async () => {
    for (const orgId of ["has.dot", "Upper", "", "-leading", "x".repeat(64)]) {
      const res = await init({ ...validBody("ignored"), orgId });
      expect(res.status).toBe(400);
      expect(((await res.json()) as any).error).toBe("invalid_body");
    }
  });

  it("missing orgName / displayName / invalid email are 400 invalid_body", async () => {
    expect((await init({ ...validBody("acme-b1"), orgName: "" })).status).toBe(400);
    expect((await init({ ...validBody("acme-b2"), displayName: "" })).status).toBe(400);
    expect((await init({ ...validBody("acme-b3"), email: "not-an-email" })).status).toBe(400);
  });

  it("a non-JSON body is 400 invalid_body", async () => {
    const res = await SELF.fetch(`${ORIGIN}/v1/setup/init`, {
      method: "POST", headers: jsonHeaders(), body: "not json",
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_body");
  });

  it("an org that already has members is 409 already_bootstrapped (flag still unset)", async () => {
    // Seed a member DIRECTLY in the OrgDO (no bootstrap — the deployment flag must stay unset so
    // this exercises the members check, not the setup_complete gate).
    const orgId = "acme-occupied";
    const org = (env as any).ORG_DO.getByName(orgId);
    await org.createUser({ orgId, email: `seed@${orgId}.test`, displayName: "Seed", role: "owner" });
    const res = await init(validBody(orgId));
    expect(res.status).toBe(409);
    expect(((await res.json()) as any).error).toBe("already_bootstrapped");
    // …and the deployment is still un-set-up.
    __resetSetupStatusCacheForTest();
    expect((await status()).body).toEqual({ needed: true });
  });
});

describe("POST /v1/setup/init — happy path + self-disable (single self-contained test)", () => {
  it("creates org+admin with a REAL password, signs in via cookie, flips status, then 409s forever", async () => {
    const orgId = "acme";
    const body = validBody(orgId);

    // 1. init → 201 + the §2.5 payload + an org-qualified session cookie.
    const res = await init(body);
    expect(res.status).toBe(201);
    const out = (await res.json()) as any;
    expect(out.orgId).toBe(orgId);
    expect(out.userId).toMatch(/^usr-/);
    expect(typeof out.csrf).toBe("string");
    expect(out.account).toEqual({ email: body.email, displayName: "Josh", role: "owner" });
    const setCookie = res.headers.get("set-cookie") ?? "";
    const m = /cfs_session=([^;]+)/.exec(setCookie);
    expect(m).toBeTruthy();
    expect(m![1].startsWith(`${orgId}.sess-`)).toBe(true);

    // 2. The operator is genuinely signed in: /me works off the cookie alone.
    const me = await SELF.fetch(`${ORIGIN}/v1/auth/me`, { headers: { cookie: `cfs_session=${m![1]}` } });
    expect(me.status).toBe(200);
    const meBody = (await me.json()) as any;
    expect(meBody.email).toBe(body.email);
    expect(meBody.role).toBe("owner");
    expect(meBody.emailVerified).toBe(true); // operator-controlled email is pre-verified
    expect(meBody.orgName).toBe("Acme Post");
    expect(meBody.csrf).toBe(out.csrf);

    // 3. The credential is REAL: a normal password login works…
    const login = await SELF.fetch(`${ORIGIN}/v1/auth/login`, {
      method: "POST", headers: jsonHeaders(),
      body: JSON.stringify({ email: body.email, password: body.password }),
    });
    expect(login.status).toBe(200);
    // …and a wrong password does not.
    const bad = await SELF.fetch(`${ORIGIN}/v1/auth/login`, {
      method: "POST", headers: jsonHeaders(),
      body: JSON.stringify({ email: body.email, password: "wrong password 123" }),
    });
    expect(bad.status).toBe(401);

    // 4. Self-disable: status flips…
    __resetSetupStatusCacheForTest(); // force a durable re-read (not just the cache update)
    const after = await status();
    expect(after.body).toEqual({ needed: false });

    // 5. …and a second init is 409 setup_complete, even for a different org id.
    const again = await init(validBody("acme-two"));
    expect(again.status).toBe(409);
    expect(((await again.json()) as any).error).toBe("setup_complete");
  });
});
