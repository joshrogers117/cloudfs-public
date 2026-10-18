// SPDX-License-Identifier: AGPL-3.0-or-later
import {env, runInDurableObject} from 'cloudflare:test';
import {expect, it} from 'vitest';
import type {Env} from '../src/env';
import type {DirectoryDO} from '../src/directory-do';

it('retains real organizations without adding rejected email, passkey or setup claimants to backup scope', async () => {
  const directory = (env as Env).DIRECTORY_DO.getByName(`backup-registry-${crypto.randomUUID()}`);
  await directory.claim('owner@example.test', 'real', 'account');
  await runInDurableObject(directory, async (instance: DirectoryDO) => {
    await expect(instance.claim('owner@example.test', 'email-collision', 'other')).rejects.toThrow();
  });
  expect(await directory.indexWebAuthn('credential', 'real', 'account')).toBe('created');
  expect(await directory.indexWebAuthn('credential', 'passkey-collision', 'other')).toBe('conflict');
  expect((await directory.acquireSetup('real', 'owner@example.test', 'claim')).status).toBe('acquired');
  expect((await directory.acquireSetup('setup-collision', 'other@example.test', 'other')).status).toBe('setup_target_mismatch');
  await directory.markSetupComplete();
  expect((await directory.acquireSetup('closed-setup', 'other@example.test', 'other')).status).toBe('setup_complete');
  await directory.release('owner@example.test');
  await directory.unindexWebAuthn('credential');
  await runInDurableObject(directory, (_instance, state) => {
    expect(state.storage.sql.exec('SELECT org_id FROM org_registry ORDER BY org_id;').toArray()).toEqual([{org_id: 'real'}]);
  });
});
