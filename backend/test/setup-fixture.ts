// SPDX-License-Identifier: AGPL-3.0-or-later
// Test-only fresh-deployment boundary. No production endpoint can reset first-owner setup.
import { env, runInDurableObject } from "cloudflare:test";
import type { Env } from "../src/env";
import { __resetSetupStatusCacheForTest } from "../src/setup";

export async function resetSetupFixture(): Promise<void> {
  const e = env as Env;
  const directory = e.DIRECTORY_DO.get(e.DIRECTORY_DO.idFromName("global"));
  await runInDurableObject(directory, async (_instance, state) => {
    state.storage.sql.exec("DELETE FROM setup_state");
    state.storage.sql.exec("DELETE FROM setup_claim");
  });
  __resetSetupStatusCacheForTest();
}

import { mintToken, type Scope } from "../src/security/auth";
export async function seedOwnerFixture(orgId: string): Promise<{ token: string; userId: string }> {
  const e = env as Env;
  const owner = await e.ORG_DO.get(e.ORG_DO.idFromName(orgId)).createUser({ orgId, email: `owner@${orgId}.test`, displayName: "Owner", role: "owner" });
  const scopes: Scope[] = ["fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write", "audit:read"];
  return { userId: owner.id, token: await mintToken(e.AUTH_SIGNING_SECRET, { sub: owner.id, type: "session", orgId, scopes, ttlSeconds: 900 }) };
}
