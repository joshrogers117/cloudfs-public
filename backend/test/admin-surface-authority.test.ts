/// <reference types="node" />
// SPDX-License-Identifier: AGPL-3.0-or-later
import { SELF, env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import { filespaceDoName, mintToken, type Scope, type TokenType } from '../src/security/auth';
import { seedOwnerFixture } from './setup-fixture';
import { HttpGatewayClient } from '../../cli/src/gateway/http';
import { ExitCode } from '../../cli/src/exit-codes';

const e = env as Env;
const origin = 'https://gw.local';
// Deliberately overprivileged or previously issued tokens: scopes never grant roles.
const scopes: Scope[] = ['fs:read', 'fs:write', 'fs:lock', 'fs:admin', 'snapshot:read', 'snapshot:write', 'audit:read'];
async function fixture(role: 'standard' | 'space_admin' | 'admin' = 'standard', type: TokenType = 'session') {
  const orgId = `admin-surface-${crypto.randomUUID()}`;
  const owner = await seedOwnerFixture(orgId);
  const org = e.ORG_DO.get(e.ORG_DO.idFromName(orgId));
  const user = await org.createUser({ orgId, email: 'member@example.test', displayName: 'Member', role });
  const token = await mintToken(e.AUTH_SIGNING_SECRET, { sub: user.id, type, orgId, scopes, ttlSeconds: 900 });
  const request = (path: string, method = 'GET', body?: unknown, bearer = token) => SELF.fetch(origin + path, {
    method, headers: { authorization: `Bearer ${bearer}`, 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const workspace = `/v1/orgs/${orgId}`;
  expect((await request(`${workspace}/spaces`, 'POST', { spaceId: 'team', name: 'Team', bucketProvider: 'r2', bucketName: 'test', keyPrefix: '' }, owner.token)).status).toBe(201);
  const fs = e.FILESPACE.get(e.FILESPACE.idFromName(filespaceDoName(orgId, 'team')));
  await fs.grantAccess({ spaceId: 'team', inodeId: 'root', principalType: type === 'service' ? 'service_account' : 'user', principalId: user.id, level: 'edit' }, owner.userId);
  const cli = new HttpGatewayClient({ baseUrl: origin, token, requestTimeoutMs: 0, maxRetries: 0, fetch: (url, init) => SELF.fetch(url, init) });
  return { request, workspace, org, user, owner, fs, cli };
}

describe('administration authority across UI, CLI and direct API access', () => {
  for (const type of ['session', 'service'] as const) {
    it(`${type}: a regular member cannot read or change administrative settings even with all token scopes`, async () => {
      const f = await fixture('standard', type);
      const routes: [string, string, unknown?][] = [
        ['/users', 'GET'], [`/users/${f.owner.userId}`, 'GET'], ['/users', 'POST', { email: 'new@example.test', role: 'admin' }],
        [`/users/${f.user.id}`, 'PATCH', { role: 'owner' }], ['/groups', 'GET'], ['/groups', 'POST', { name: 'Admins' }],
        ['/invites', 'GET'], ['/invites', 'POST', { email: 'new@example.test', role: 'admin' }],
        ['/shares', 'GET'], ['/shares', 'POST', { spaceId: 'team', inodeId: 'root' }], ['/shares/nonexistent', 'DELETE'],
        ['/storage/default', 'GET'], ['/storage-credentials', 'GET'], ['/storage-credentials', 'POST', {}],
        ['/email-config', 'GET'], ['/email-config', 'PUT', {}], ['/auth-config', 'GET'], ['/auth-config', 'PUT', {}],
        ['/service-tokens', 'GET'], ['/service-tokens', 'POST', {}], ['/doctor', 'GET'],
        ['', 'PATCH', { name: 'Hijacked' }], ['/spaces', 'POST', { spaceId: 'extra', name: 'Extra' }],
        ['/spaces/team', 'PATCH', { name: 'Hijacked' }], ['/spaces/team', 'PATCH', { storageBucket: 'hijacked' }],
        ['/spaces/team', 'DELETE'], ['/spaces/team/purge', 'GET'], ['/spaces/team/purge', 'POST', { confirm: 'team' }],
      ];
      for (const [path, method, body] of routes) expect((await f.request(f.workspace + path, method, body)).status, `${method} ${path}`).toBe(403);
      for (const [path, method, body] of [
        ['/audit', 'GET'], ['/activity/live', 'GET'], ['/schedules', 'GET'],
        ['/schedules', 'POST', { id: 'daily', tier: 'daily', intervalMs: 86400000, retain: 7 }],
        ['/schedules/daily', 'PATCH', { enabled: false }], ['/schedules/daily', 'DELETE'],
        ['/snapshots', 'POST', { scope: 'root' }],
        ['/grants', 'POST', { inodeId: 'root', principalType: 'user', principalId: f.user.id, level: 'admin' }],
      ] as [string, string, unknown?][]) expect((await f.request('/v1/filespaces/team' + path, method, body)).status, `${method} ${path}`).toBe(403);
      // Ordinary file operations remain usable; listing strips the storage descriptor.
      const spaces = await (await f.request(f.workspace + '/spaces')).json() as Record<string, unknown>[];
      expect(spaces).toHaveLength(1);
      expect(spaces[0]).not.toHaveProperty('storageBucket');
      expect((await f.request('/v1/filespaces/team/items', 'POST', { parent: 'root', name: 'normal.txt', isDir: false, size: 0 })).status).toBe(201);
      expect((await f.request('/v1/filespaces/team/items?parent=root')).status).toBe(200);
    });
  }

  it('the real CLI HTTP client receives permission denied for admin commands', async () => {
    const { cli } = await fixture('standard', 'service');
    for (const operation of [
      () => cli.usersList(), () => cli.groupsList(), () => cli.userCreate({ email: 'other@example.test', role: 'admin' }),
      () => cli.groupCreate('Admins'), () => cli.inviteList(), () => cli.inviteCreate({ email: 'other@example.test', role: 'admin' }),
      () => cli.shareList('team'), () => cli.shareCreate({ filespace: 'team', path: '/', kind: 'guest' }),
      () => cli.createFilespace({ name: 'Extra', bucket: 's3://test' }), () => cli.snapshotCreate({ filespace: 'team' }),
      () => cli.permissionGrant({ filespace: 'team', path: '/', principal: 'user:unknown', level: 'admin', expiresAt: null }),
    ]) await expect(operation()).rejects.toMatchObject({ code: ExitCode.PERMISSION_DENIED });
  });

  it('demotion takes effect on the next administrative request with the SAME token', async () => {
    const f = await fixture('admin');
    expect((await f.request(f.workspace + '/users')).status).toBe(200);
    expect((await f.request('/v1/filespaces/team/audit')).status).toBe(200);
    await f.org.setUserRole(f.user.id, 'standard');
    expect((await f.request(f.workspace + '/users')).status).toBe(403);
    expect((await f.request(f.workspace + '/spaces/team', 'PATCH', { name: 'No' })).status).toBe(403);
    expect((await f.request(f.workspace + '/shares')).status).toBe(403);
    expect((await f.request('/v1/filespaces/team/audit')).status).toBe(403);
    expect((await f.request('/v1/filespaces/team/snapshots', 'POST', { scope: 'root' })).status).toBe(403);
  });

  it('filespace admins cannot administer workspace accounts but retain filespace controls', async () => {
    const f = await fixture('space_admin');
    for (const path of ['/users', '/groups', '/invites', '/storage/default', '/email-config']) {
      expect((await f.request(f.workspace + path)).status).toBe(403);
    }
    expect((await f.request(f.workspace + '/spaces/team', 'PATCH', { name: 'Renamed' })).status).toBe(200);
    expect((await f.request(f.workspace + '/shares')).status).toBe(200);
    expect((await f.request('/v1/filespaces/team/schedules')).status).toBe(403);
    expect((await f.request('/v1/filespaces/team/audit')).status).toBe(403);
  });

  it('folder administrators retain scoped access without acquiring workspace settings', async () => {
    const f = await fixture();
    const result = await f.fs.createItem('root', 'Delegated', true, 0);
    if (!('item' in result)) throw new Error('fixture failed');
    await f.fs.grantAccess({ spaceId: 'team', inodeId: result.item.id, principalType: 'user', principalId: f.user.id, level: 'admin' }, f.owner.userId);
    const management = await (await f.request('/v1/filespaces/team/access-management')).json() as { canManageAccess: boolean; canManageWorkspace: boolean };
    expect(management.canManageAccess).toBe(true);
    expect(management.canManageWorkspace).toBe(false);
    expect((await f.request('/v1/filespaces/team/snapshots', 'POST', { scope: result.item.id })).status).toBe(201);
    expect((await f.request('/v1/filespaces/team/snapshots', 'POST', { scope: 'root' })).status).toBe(403);
    expect((await f.request(f.workspace + '/invites')).status).toBe(403);
  });
});
