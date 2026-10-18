// SPDX-License-Identifier: AGPL-3.0-or-later
// An authenticated owner upgrades its pre-AuthDO membership, keeping the same ACL identity.
// This never accepts a service token, never enrolls someone else, and never resets an account.
import type { Env } from './env';
import type { Principal } from './security/auth';
import { verifyToken } from './security/auth';
import { authStoresFor } from './auth-stores';
import { issueEmailToken, inspectEmailToken } from './security/auth-email';
import { hashPassword, scryptCostFromEnv } from './security/auth-password';
import { webBaseUrl } from './auth-wiring';
import { markDeploymentSetupComplete } from './setup';

function json(body: unknown, status = 200) {
  return Response.json(body, { status, headers: { 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' } });
}

export async function prepareLegacyAccount(req: Request, env: Env, principal: Principal): Promise<Response> {
  try {
    return await prepare(req, env, principal);
  } catch (error) {
    // Preparation never handles a password. Keep request bodies, bearer tokens and links out of logs.
    console.error({ event: 'legacy_account_migration_failed', message: error instanceof Error ? error.message : 'authority unavailable' });
    return json({ error: 'migration_unavailable' }, 503);
  }
}

async function prepare(req: Request, env: Env, principal: Principal): Promise<Response> {
  if (req.method !== 'POST') return json({ error: 'method not allowed' }, 405);
  if (principal.type !== 'session' || principal.spaceId) return json({ error: 'owner_session_required' }, 403);
  const orgId = principal.orgId;
  const org = env.ORG_DO.getByName(orgId);
  // Read the authority directly, without the normal short-lived ACL cache.
  const owner = await org.getUser(principal.sub);
  if (!owner || owner.role !== 'owner' || owner.status !== 'active' || owner.kind !== 'human') {
    return json({ error: 'owner_session_required' }, 403);
  }
  const body = await req.json().catch(() => null) as { recoverPassword?: boolean } | null;
  const recover = body?.recoverPassword === true;
  const proof = recover ? await operatorRecoveryProof(req, env, principal) : null;
  if (recover && !proof) return json({ error: 'operator_proof_required' }, 403);
  const directory = env.DIRECTORY_DO.getByName('global');
  const email = owner.email.trim().toLowerCase();
  const existing = await directory.resolve(email);
  const auth = env.AUTH_DO.getByName(orgId);
  const prior = await auth.getAccountByUserId(owner.id);
  if (existing && (existing.orgId !== orgId || existing.accountId !== prior?.id)) {
    return json({ error: 'email_taken' }, 409);
  }
  const migration = await auth.provisionLegacyOwner({ orgId, userId: owner.id, email, displayName: owner.displayName });
  if (!migration) return json({ error: 'account_conflict' }, 409);
  try {
    await directory.claim(email, orgId, migration.account.id);
  } catch {
    // A partial local account is safe to retry; never release another account's email.
    return json({ error: 'email_taken' }, 409);
  }
  if (!await directory.completeLegacySetup(orgId, email)) return json({ error: 'setup_in_progress' }, 409);
  await markDeploymentSetupComplete(env);
  if (proof) {
    if (!await auth.claimOperatorRecovery(proof.jti, migration.account.id, proof.expiresAt)) return json({ error: 'operator_proof_used' }, 409);
    const issued = await issueEmailToken(authStoresFor(env, orgId).emailTokens, {
      orgId, accountId: migration.account.id, email, purpose: 'password_reset', ttlSeconds: 30 * 60,
    });
    const fragment = new URLSearchParams({ orgId, token: issued.token });
    return json({ status: 'password_recovery_required', expiresAt: issued.record.expiresAt,
      passwordRecoveryUrl: `${webBaseUrl(env, req)}/reset-password#${fragment}` }, 201);
  }
  if (!migration.pending) return json({ status: 'ready', passwordConfigured: !!await auth.getPassword(migration.account.id),
    signInUrl: `${webBaseUrl(env, req)}/signin` });
  const stores = authStoresFor(env, orgId);
  const issued = await issueEmailToken(stores.emailTokens, {
    orgId, accountId: migration.account.id, email, purpose: 'legacy_enrollment',
  });
  // Fragment prevents the bearer capability from reaching HTTP access/referrer logs.
  const fragment = new URLSearchParams({ orgId, token: issued.token });
  return json({ status: 'enrollment_required', email, expiresAt: issued.record.expiresAt,
    enrollmentUrl: `${webBaseUrl(env, req)}/finish-sign-in#${fragment}` }, 201);
}

/** Ordinary owner login/device tokens cannot request a reset without a password.
 * This distinct, origin-bound assertion can only be made with the deployment's signing key.
 * It expires in two minutes and is consumed durably before any reset link is returned. */
async function operatorRecoveryProof(req: Request, env: Env, principal: Principal) {
  try {
    const token = req.headers.get('authorization')?.match(/^Bearer (.+)$/i)?.[1];
    if (!token) return null;
    const verified = await verifyToken(env.AUTH_SIGNING_SECRET, token);
    if (verified.sub !== principal.sub || verified.orgId !== principal.orgId || verified.type !== 'session') return null;
    const claims = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    const expectedAudience = `${new URL(env.PUBLIC_BASE_URL || req.url).origin}/v1/operator/legacy-password-recovery`;
    const now = Math.floor(Date.now() / 1000);
    if (claims.aud !== expectedAudience || claims.act !== 'legacy-password-recovery' ||
        !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp) ||
        claims.iat > now || claims.exp <= now || claims.exp - claims.iat > 120 || claims.exp <= claims.iat) return null;
    return { jti: verified.jti, expiresAt: claims.exp * 1000 };
  } catch { return null; }
}

/** Rate limiting, password policy and auth-provider mode are applied by auth-wiring. */
export async function completeLegacyAccount(env: Env, body: { orgId: string; token: string; newPassword: string }): Promise<Response> {
  const stores = authStoresFor(env, body.orgId);
  const verified = await inspectEmailToken(stores.emailTokens, body.token, 'legacy_enrollment');
  if (!verified.ok) return json({ error: 'invalid_enrollment' }, 400);
  const account = await stores.accounts.getAccount(verified.record.accountId);
  if (!account || account.orgId !== body.orgId || account.email !== verified.record.email) return json({ error: 'invalid_enrollment' }, 400);
  const owner = await env.ORG_DO.getByName(body.orgId).getUser(account.userId);
  if (!owner || owner.status !== 'active' || owner.role !== 'owner' || owner.kind !== 'human' ||
      owner.email.trim().toLowerCase() !== account.email) return json({ error: 'invalid_enrollment' }, 400);
  const entry = await env.DIRECTORY_DO.getByName('global').resolve(account.email);
  if (entry?.orgId !== body.orgId || entry.accountId !== account.id) return json({ error: 'invalid_enrollment' }, 400);
  const credential = await hashPassword(account.id, body.newPassword, { cost: scryptCostFromEnv(env) });
  if (!await env.AUTH_DO.getByName(body.orgId).completeLegacyEnrollment(verified.record, credential)) {
    return json({ error: 'invalid_enrollment' }, 400);
  }
  // The owner now uses the ordinary password + MFA login and browser-device approval.
  return json({ ok: true });
}
