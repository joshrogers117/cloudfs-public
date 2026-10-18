// SPDX-License-Identifier: AGPL-3.0-or-later
import { env, runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import { migrate } from '../src/metadata/schema';
const bindings = env as Env;

describe('lease purpose v30 migration', () => {
  it('preserves an active v29 lease and classifies it as advisory', async () => {
    await runInDurableObject(bindings.FILESPACE.getByName(crypto.randomUUID()), async (_fs, state) => {
      const sql = state.storage.sql;
      const acquiredAt = 1_700_000_000_000;
      const expiresAt = Date.now() + 60_000;
      sql.exec('DROP TABLE locks;');
      sql.exec(`CREATE TABLE locks (
        path TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        mode TEXT NOT NULL DEFAULT 'exclusive',
        fence INTEGER NOT NULL,
        acquired_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );`);
      sql.exec('CREATE INDEX locks_expiry ON locks(expires_at);');
      sql.exec('DELETE FROM _schema_migrations WHERE id=30;');
      sql.exec(`INSERT INTO locks(path,owner,mode,fence,acquired_at,expires_at)
        VALUES(?,?,?,?,?,?);`, 'ino-active', 'owner:device', 'exclusive', 91, acquiredAt, expiresAt);

      migrate(sql);

      const lease = sql.exec(`SELECT path,owner,mode,fence,acquired_at,expires_at,purpose FROM locks WHERE path=?;`, 'ino-active').one();
      expect(lease).toMatchObject({
        path: 'ino-active', owner: 'owner:device', mode: 'exclusive', fence: 91,
        acquired_at: acquiredAt, expires_at: expiresAt, purpose: 'advisory',
      });
      expect(Number(sql.exec('SELECT MAX(id) AS version FROM _schema_migrations;').one().version)).toBe(30);
    });
  });
});
