// SPDX-License-Identifier: AGPL-3.0-or-later
import { SELF, env, runInDurableObject } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import { resetSetupFixture, seedOwnerFixture } from './setup-fixture';
import { mintToken } from '../src/security/auth';
import { hashPassword, verifyPassword } from '../src/security/auth-password';
import { authStoresFor } from '../src/auth-stores';
import { issueEmailToken } from '../src/security/auth-email';
const e = env as Env;
let sequence = 0;
const password = 'a new legacy password 1234';
function post(path: string, body: unknown = {}, headers: Record<string, string> = {}) {
  return SELF.fetch(`https://gw.local${path}`, { method: 'POST', headers: {
    'content-type': 'application/json', 'cf-connecting-ip': `198.19.0.${++sequence}`, ...headers,
  }, body: JSON.stringify(body) });
}
async function fixture() {
  const orgId = `legacy-${++sequence}`;
  const owner = await seedOwnerFixture(orgId);
  const org = e.ORG_DO.getByName(orgId);
  await org.createServiceAccount({ orgId, name: 'Existing Mac' });
  await org.createUser({ orgId, email: `second@${orgId}.test`, displayName: 'Second owner', role: 'owner' });
  const prepare = () => post(`/v1/orgs/${orgId}/legacy-account`, {}, { authorization: `Bearer ${owner.token}` });
  return { orgId, ...owner, org, auth: e.AUTH_DO.getByName(orgId), email: `owner@${orgId}.test`, prepare };
}
async function enrollment(f: Awaited<ReturnType<typeof fixture>>) {
  const response = await f.prepare();
  expect(response.status).toBe(201);
  expect(response.headers.get('cache-control')).toBe('no-store');
  const body = await response.json() as { enrollmentUrl: string };
  const url = new URL(body.enrollmentUrl);
  expect(url.search).toBe('');
  const params = new URLSearchParams(url.hash.slice(1));
  return { orgId: f.orgId, token: params.get('token')!, newPassword: password };
}
const complete = (body: unknown) => post('/v1/auth/password/enroll-legacy', body);
async function operatorToken(f: Awaited<ReturnType<typeof fixture>>, patch: Record<string, unknown> = {}) {
  const iat = Math.floor(Date.now() / 1000);
  const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  const enc = (o: unknown) => b64(new TextEncoder().encode(JSON.stringify(o)));
  const audience = `${new URL(e.PUBLIC_BASE_URL || 'https://gw.local').origin}/v1/operator/legacy-password-recovery`;
  const text = `${enc({ alg: 'HS256', typ: 'JWT' })}.${enc({ sub: f.userId, typ: 'session', org: f.orgId, scp: ['fs:read'],
    jti: `operator-${crypto.randomUUID()}`, iat, exp: iat + 120, aud: audience, act: 'legacy-password-recovery', ...patch })}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(e.AUTH_SIGNING_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return `${text}.${b64(new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(text))))}`;
}
beforeEach(resetSetupFixture);

describe('legacy membership migration', () => {
  it('requires distinct operator authority for recovery; a normal owner token cannot issue a reset', async () => {
    const f = await fixture();
    const path = `/v1/orgs/${f.orgId}/legacy-account`;
    expect((await post(path, { recoverPassword: true }, { authorization: `Bearer ${f.token}` })).status).toBe(403);
    for (const patch of [{ aud: 'https://other.test/v1/operator/legacy-password-recovery' }, { act: 'ordinary-login' },
      { exp: Math.floor(Date.now() / 1000) + 600 }, { exp: Math.floor(Date.now() / 1000) - 1 }, { typ: 'service' }]) {
      const token = await operatorToken(f, patch);
      expect([401, 403]).toContain((await post(path, { recoverPassword: true }, { authorization: `Bearer ${token}` })).status);
    }
    expect(await f.auth.getAccountByUserId(f.userId)).toBeNull();
  });

  it('operator recovery uses normal single-use password reset and cannot replay after the reset', async () => {
    const f = await fixture();
    expect((await complete(await enrollment(f))).status).toBe(200);
    const account = (await f.auth.getAccountByUserId(f.userId))!;
    await f.auth.beginTotpEnrollment({ accountId: account.id, secret: 'preserved-mfa-secret', confirmed: false, createdAt: Date.now(), confirmedAt: null });
    const token = await operatorToken(f);
    const request = () => post(`/v1/orgs/${f.orgId}/legacy-account`, { recoverPassword: true }, { authorization: `Bearer ${token}` });
    const response = await request();
    expect(response.status).toBe(201);
    const result = await response.json() as { passwordRecoveryUrl: string };
    const url = new URL(result.passwordRecoveryUrl);
    expect(url.pathname).toBe('/reset-password');
    expect(url.search).toBe('');
    const params = new URLSearchParams(url.hash.slice(1));
    const body = { orgId: f.orgId, token: params.get('token'), newPassword: 'recovered owner password 1234' };
    expect((await request()).status).toBe(409);
    expect((await post('/v1/auth/password/reset', body)).status).toBe(204);
    expect((await request()).status).toBe(409);
    expect((await post('/v1/auth/password/reset', body)).status).toBe(400);
    expect(await verifyPassword((await f.auth.getPassword(account.id))!, body.newPassword)).toBe(true);
    expect((await f.auth.getTotp(account.id))?.secret).toBe('preserved-mfa-secret');
    expect(await f.org.countUsers()).toBe(3);
  });
  it('preserves membership and supports password login, browser session, PKCE, refresh, and a daemon token', async () => {
    const f = await fixture();
    const before = await f.org.listUsers();
    const body = await enrollment(f);
    expect(await (await SELF.fetch('https://gw.local/v1/setup/status')).json()).toEqual({ needed: false });
    expect((await complete(body)).status).toBe(200);
    expect(await f.org.listUsers()).toEqual(before);
    expect(await e.DIRECTORY_DO.getByName('global').getSetupOrgId()).toBe(f.orgId);
    const login = await post('/v1/auth/login', { email: f.email.toUpperCase(), password });
    expect(login.status).toBe(200);
    const signed = await login.json() as { csrf: string };
    const cookie = login.headers.get('set-cookie')!.split(';')[0];
    expect((await SELF.fetch('https://gw.local/v1/auth/me', { headers: { cookie } })).status).toBe(200);
    const verifier = 'v'.repeat(43);
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
    const challenge = btoa(String.fromCharCode(...new Uint8Array(hash))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const approved = await post('/v1/auth/device/approve', { codeChallenge: challenge, codeChallengeMethod: 'S256', deviceName: 'Migration test Mac', state: 's'.repeat(43) }, { cookie, 'X-CFS-CSRF': signed.csrf });
    expect(approved.status).toBe(201);
    const code = (await approved.json() as { code: string }).code;
    const exchange = await post('/v1/auth/device/token', { code, codeVerifier: verifier });
    expect(exchange.status).toBe(200);
    const device = await exchange.json() as { refreshToken: string; accessToken: string };
    expect((await post('/v1/auth/device/token', { code, codeVerifier: verifier })).status).toBe(400);
    expect((await post('/v1/auth/device/refresh', { refreshToken: device.refreshToken })).status).toBe(200);
    expect((await post('/v1/auth/device/daemon-token', {}, { authorization: `Bearer ${device.accessToken}` })).status).toBe(201);
    expect((await complete(body)).status).toBe(400);
    expect((await f.prepare()).status).toBe(200);
  });

  it('refuses unauthenticated callers, service tokens, non-owners, and suspended owners', async () => {
    const f = await fixture();
    const path = `/v1/orgs/${f.orgId}/legacy-account`;
    expect((await post(path)).status).toBe(401);
    const service = await mintToken(e.AUTH_SIGNING_SECRET, { sub: f.userId, type: 'service', orgId: f.orgId, scopes: ['fs:read'], ttlSeconds: 900 });
    expect((await post(path, {}, { authorization: `Bearer ${service}` })).status).toBe(403);
    await f.org.setUserRole(f.userId, 'standard');
    expect((await f.prepare()).status).toBe(403);
    await f.org.setUserRole(f.userId, 'owner');
    await f.org.setUserStatus(f.userId, 'suspended');
    expect([401, 403]).toContain((await f.prepare()).status);
    expect(await f.auth.getAccountByUserId(f.userId)).toBeNull();
  });

  it('never grants enrollment over an existing passwordless or password account; repairs its directory', async () => {
    const f = await fixture();
    const account = await f.auth.createAccount({ orgId: f.orgId, userId: f.userId, email: f.email, displayName: 'Owner', role: 'owner', emailVerified: true });
    let response = await f.prepare();
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ status: 'ready' });
    await f.auth.putPassword(await hashPassword(account.id, password, { cost: { N: 1024, r: 8, p: 1, dkLen: 32 } }));
    response = await f.prepare();
    expect(response.status).toBe(200);
    expect(await e.DIRECTORY_DO.getByName('global').resolve(f.email)).toEqual({ orgId: f.orgId, accountId: account.id });
  });

  it('refuses cross-tenant email claims and preserves an unrelated setup in progress', async () => {
    const f = await fixture();
    const directory = e.DIRECTORY_DO.getByName('global');
    await directory.claim(f.email, 'other', 'other-account');
    expect((await f.prepare()).status).toBe(409);
    expect(await f.auth.getAccountByUserId(f.userId)).toBeNull();
    const second = await fixture();
    await directory.acquireSetup('unrelated', 'other@example.test', 'lease');
    expect((await second.prepare()).status).toBe(409);
    expect(await directory.getSetupComplete()).toBe(false);
  });

  it('resumes partial migration, rejects weak passwords without consuming the link, and commits only one racing password', async () => {
    const f = await fixture();
    const initial = await f.auth.provisionLegacyOwner({ orgId: f.orgId, userId: f.userId, email: f.email, displayName: 'Owner' });
    const body = await enrollment(f);
    expect((await f.auth.getAccountByUserId(f.userId))!.id).toBe(initial!.account.id);
    expect((await complete({ ...body, newPassword: 'short' })).status).toBe(400);
    const results = await Promise.all([complete(body), complete({ ...body, newPassword: 'another strong password 1234' })]);
    expect(results.map(r => r.status).sort()).toEqual([200, 400]);
    const cred = await f.auth.getPassword(initial!.account.id);
    const expected = results[0].status === 200 ? password : 'another strong password 1234';
    expect(await verifyPassword(cred!, expected)).toBe(true);
  });

  it('rejects wrong-purpose, wrong-tenant, expired, superseded and altered tokens', async () => {
    const f = await fixture();
    const old = await enrollment(f);
    const body = await enrollment(f);
    expect((await complete(old)).status).toBe(400);
    expect((await complete({ ...body, orgId: 'other' })).status).toBe(400);
    expect((await complete({ ...body, token: body.token.slice(0, -3) + 'zzz' })).status).toBe(400);
    const account = (await f.auth.getAccountByUserId(f.userId))!;
    const reset = await issueEmailToken(authStoresFor(e, f.orgId).emailTokens, { orgId: f.orgId, accountId: account.id, email: f.email, purpose: 'password_reset' });
    expect((await complete({ ...body, token: reset.token })).status).toBe(400);
    await runInDurableObject(f.auth, (_i, state) => { state.storage.sql.exec(`UPDATE email_tokens SET expires_at=0 WHERE purpose='legacy_enrollment'`); });
    expect((await complete(body)).status).toBe(400);
    expect(await f.auth.getPassword(account.id)).toBeNull();
  });

  for (const change of ['suspend', 'demote', 'password', 'passkey', 'totp'] as const) {
    it(`revalidates enrollment after ${change}`, async () => {
      const f = await fixture();
      const body = await enrollment(f);
      const account = (await f.auth.getAccountByUserId(f.userId))!;
      if (change === 'suspend') await f.org.setUserStatus(f.userId, 'suspended');
      if (change === 'demote') await f.org.setUserRole(f.userId, 'standard');
      if (change === 'password') await f.auth.putPassword(await hashPassword(account.id, 'keep existing password', { cost: { N: 1024, r: 8, p: 1, dkLen: 32 } }));
      if (change === 'totp') await f.auth.beginTotpEnrollment({ accountId: account.id, secret: 'secret', confirmed: false, createdAt: Date.now(), confirmedAt: null });
      if (change === 'passkey') await runInDurableObject(f.auth, (_i, state) => { state.storage.sql.exec(`INSERT INTO webauthn_creds (id,account_id,credential_id,public_key,sign_count,transports,created_at) VALUES ('key',?,'key','public',0,'[]',0);`, account.id); });
      expect((await complete(body)).status).toBe(400);
      if (change === 'password') expect(await verifyPassword((await f.auth.getPassword(account.id))!, 'keep existing password')).toBe(true);
    });
  }
});
