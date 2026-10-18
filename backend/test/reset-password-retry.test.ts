// SPDX-License-Identifier: AGPL-3.0-or-later
import { SELF, env } from 'cloudflare:test';
import { expect, it } from 'vitest';
import type { Env } from '../src/env';
import { authStoresFor } from '../src/auth-stores';
import { issueEmailToken } from '../src/security/auth-email';
import { setPassword } from '../src/security/auth-password';
const e = env as Env;
it('a rejected new password leaves the reset link usable, and a successful reset consumes it', async () => {
  const orgId = 'reset-retry';
  const org = e.ORG_DO.get(e.ORG_DO.idFromName(orgId));
  const owner = await org.createUser({orgId,email:'owner@reset-retry.test',displayName:'Owner',role:'owner'});
  const stores = authStoresFor(e,orgId);
  const account = await stores.accounts.createAccount({orgId,userId:owner.id,email:owner.email,displayName:owner.displayName,role:'owner',emailVerified:true});
  await setPassword(stores.credentials,account.id,'initial reset password',{cost:{N:2}});
  const issued = await issueEmailToken(stores.emailTokens,{orgId,accountId:account.id,email:account.email,purpose:'password_reset'});
  const reset = (newPassword: string) => SELF.fetch('https://gw.local/v1/auth/password/reset',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({orgId,token:issued.token,newPassword})});
  expect((await reset('short')).status).toBe(400);
  expect((await stores.emailTokens.get(issued.record.id))!.consumedAt).toBeNull();
  expect((await reset('x'.repeat(1025))).status).toBe(400);
  expect((await stores.emailTokens.get(issued.record.id))!.consumedAt).toBeNull();
  expect((await reset('new secure reset password')).status).toBe(204);
  expect((await reset('another secure reset password')).status).toBe(400);
  const login = await SELF.fetch('https://gw.local/v1/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:account.email,password:'new secure reset password'})});
  expect(login.status).toBe(200);
});
