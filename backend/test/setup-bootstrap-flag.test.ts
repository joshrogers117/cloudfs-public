// SPDX-License-Identifier: AGPL-3.0-or-later
// setup-bootstrap-flag.test.ts — auth-spec §2.5/§4.4: a successful LEGACY `POST /v1/bootstrap`
// also marks the deployment set-up, so `GET /v1/setup/status` flips and the web wizard
// self-disables. Kept in its OWN file (separate from setup-wizard.test.ts) because the wizard
// happy path there completes setup itself, which would mask this flip.

import { SELF, env } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import { __resetSetupStatusCacheForTest } from "../src/setup";

const ORIGIN = "https://gw.local";
const BOOT_SECRET = (env as any).BOOTSTRAP_SECRET as string;

beforeEach(() => __resetSetupStatusCacheForTest());

describe("legacy bootstrap sets the setup flag", () => {
  // NOTE: the failing-bootstrap case runs FIRST — the success case below durably sets the
  // deployment flag, and test order must not depend on the pool's storage-isolation granularity.
  it("a FAILED bootstrap (password_required) does NOT set the flag", async () => {
    const before = (await (await SELF.fetch(`${ORIGIN}/v1/setup/status`)).json()) as any;
    expect(before).toEqual({ needed: true });

    const orgId = `org-noflag-${crypto.randomUUID().slice(0, 8)}`;
    const boot = await SELF.fetch(`${ORIGIN}/v1/bootstrap`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-bootstrap-secret": BOOT_SECRET },
      body: JSON.stringify({ orgId, email: `owner@${orgId}.test`, displayName: "Owner" }),
    });
    expect(boot.status).toBe(400);

    __resetSetupStatusCacheForTest();
    const after = (await (await SELF.fetch(`${ORIGIN}/v1/setup/status`)).json()) as any;
    expect(after).toEqual({ needed: true });
  });

  it("status: needed:true → bootstrap (allowTokenOnly) → needed:false", async () => {
    const before = (await (await SELF.fetch(`${ORIGIN}/v1/setup/status`)).json()) as any;
    expect(before).toEqual({ needed: true });

    const orgId = `org-flag-${crypto.randomUUID().slice(0, 8)}`;
    const boot = await SELF.fetch(`${ORIGIN}/v1/bootstrap`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-bootstrap-secret": BOOT_SECRET },
      body: JSON.stringify({ orgId, email: `owner@${orgId}.test`, displayName: "Owner", allowTokenOnly: true }),
    });
    expect(boot.status).toBe(201);

    __resetSetupStatusCacheForTest(); // re-read the durable flag, not the in-isolate cache
    const after = (await (await SELF.fetch(`${ORIGIN}/v1/setup/status`)).json()) as any;
    expect(after).toEqual({ needed: false });
  });
});
