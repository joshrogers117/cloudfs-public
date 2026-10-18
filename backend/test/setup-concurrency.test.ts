// SPDX-License-Identifier: AGPL-3.0-or-later
import { SELF, env } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
import type { Env } from "../src/env";
import { resetSetupFixture } from "./setup-fixture";
import { provisionFirstOwner, SetupError } from "../src/setup";
const e = env as Env;
let counter = 0;
const body = (orgId: string) => ({ secret: e.BOOTSTRAP_SECRET, orgId, orgName: 'Team', email: `owner@${orgId}.test`, displayName: 'Owner', password: 'safe setup password 1234' });
const init = (orgId: string) => SELF.fetch('https://gw.local/v1/setup/init', { method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': `198.18.1.${++counter}` }, body: JSON.stringify(body(orgId)) });
beforeEach(resetSetupFixture);

describe('deployment-wide first owner', () => {
  it('racing different workspaces creates exactly one owner; both entry points then close', async () => {
    const ids = ['setup-race-a', 'setup-race-b'];
    const results = await Promise.all(ids.map(init));
    expect(results.map(r => r.status).sort()).toEqual([201, 409]);
    const counts = await Promise.all(ids.map(id => e.ORG_DO.get(e.ORG_DO.idFromName(id)).countUsers()));
    expect(counts.reduce((a, b) => a + b, 0)).toBe(1);
    const legacy = await SELF.fetch('https://gw.local/v1/bootstrap', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body('setup-race-c')) });
    expect(legacy.status).toBe(409);
    expect(await legacy.json()).toMatchObject({ error: 'setup_complete' });
  });

  it('racing the same workspace does not duplicate the owner account', async () => {
    const results = await Promise.all([init('setup-same'), init('setup-same')]);
    expect(results.map(r => r.status).sort()).toEqual([201, 409]);
    expect(await e.ORG_DO.get(e.ORG_DO.idFromName('setup-same')).countUsers()).toBe(1);
  });

  it('resumes a partial owner after an expired request without duplicating it', async () => {
    const orgId = 'setup-resume';
    const input = body(orgId);
    const directory = e.DIRECTORY_DO.get(e.DIRECTORY_DO.idFromName('global'));
    expect((await directory.acquireSetup(orgId, input.email, 'crashed-request')).status).toBe('acquired');
    const org = e.ORG_DO.get(e.ORG_DO.idFromName(orgId));
    const owner = await org.provisionSetupOwner({ ...input, resumed: false });
    await directory.releaseSetup('crashed-request');
    const result = await init(orgId);
    expect(result.status).toBe(201);
    expect(await result.json()).toMatchObject({ userId: owner!.id });
    expect(await org.countUsers()).toBe(1);
  });

  it('rejects missing signing configuration before creating any owner', async () => {
    const input = body('setup-bad-config');
    await expect(provisionFirstOwner({ ...e, AUTH_SIGNING_SECRET: '' }, input)).rejects.toBeInstanceOf(SetupError);
    expect(await e.ORG_DO.get(e.ORG_DO.idFromName(input.orgId)).countUsers()).toBe(0);
  });
});
