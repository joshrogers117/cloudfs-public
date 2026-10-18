// SPDX-License-Identifier: AGPL-3.0-or-later
import { env, runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import { BackupState, type BackupEnv } from '../src/backup-state';

describe('large metadata recovery', () => {
  it('round trips 100,000 inodes with bounded pages, interrupted staging and exact page digests', async () => {
    const namespace = (env as Env).FILESPACE;
    const source = namespace.getByName(crypto.randomUUID()), target = namespace.getByName(crypto.randomUUID());
    const generation = 'scale-recovery-generation';
    const manifest = await runInDurableObject(source, (_instance, state) => {
      state.storage.sql.exec(`DELETE FROM items WHERE id!='root';`);
      state.storage.sql.exec(`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<100000)
        INSERT INTO items(id,parent,name,is_dir,size,content_version,created_seq,updated_seq)
        SELECT 'scale-'||x,'root',printf('asset-%06d',x),0,0,'version-'||x,x+1,x+1 FROM n;`);
      state.storage.sql.exec(`UPDATE meta SET value=100001 WHERE key='seq';`);
      const backup = new BackupState(state.storage, {BACKUP_MODE: 'export'}, 'filespace');
      backup.initialize(); backup.freeze({backupId: generation, mode: 'export'});
      return backup.describe();
    });
    await runInDurableObject(target, (_instance, state) => {
      state.storage.sql.exec(`DELETE FROM items WHERE id!='root';`);
      state.storage.sql.exec(`UPDATE items SET version=1,created_seq=1,updated_seq=1 WHERE id='root'; UPDATE meta SET value=1 WHERE key='seq';`);
      const backup = new BackupState(state.storage, {BACKUP_MODE: 'restore'}, 'filespace');
      backup.initialize(); backup.freeze({backupId: generation, mode: 'restore'});
      backup.restoreBegin({backupId: generation, manifest});
    });
    let pageIndex = 0, inodePages = 0;
    const expected: string[] = [];
    for (const table of manifest.tables) {
      let afterRowId: number | undefined;
      do {
        const page = await runInDurableObject(source, (_instance, state) => {
          const backup = new BackupState(state.storage, {BACKUP_MODE: 'export'}, 'filespace');
          backup.initialize(); return backup.exportPage({backupId: generation, table: table.name, afterRowId});
        });
        expect(new TextEncoder().encode(JSON.stringify(page)).length).toBeLessThan(1024 * 1024 + 4096);
        if (table.name === 'items') { inodePages++; expected.push(page.digest); }
        await runInDurableObject(target, (_instance, state) => {
          // Recreate the helper on every page, including duplicate retry pages.
          const backup = new BackupState(state.storage, {BACKUP_MODE: 'restore'}, 'filespace');
          backup.initialize(); backup.restorePage({...page, backupId: generation, pageIndex});
          if (pageIndex % 7 === 0) backup.restorePage({...page, backupId: generation, pageIndex});
          expect(state.storage.sql.exec(`SELECT COUNT(*) AS n FROM items;`).one().n).toBe(1);
        });
        pageIndex++; afterRowId = page.nextRowId ?? undefined;
      } while (afterRowId !== undefined);
    }
    expect(inodePages).toBeGreaterThan(30);
    await runInDurableObject(target, (_instance, state) => {
      const config: BackupEnv = {BACKUP_MODE: 'restore'}, backup = new BackupState(state.storage, config, 'filespace');
      // Final validation reads a bounded portion of staging before promotion.
      // Its SQL cursor must be exhausted even though more inode pages remain.
      backup.initialize();
      expect(backup.catalogPage({backupId: generation, table: 'items'}).nextRowId).not.toBeNull();
      backup.validateCatalog({backupId: generation, organizations: ['scale'], orgId: 'scale'});
      backup.verifyObjects({backupId: generation, expectedCount: 0});
      backup.restoreCommit({backupId: generation, pageCount: pageIndex});
      expect(state.storage.sql.exec(`SELECT COUNT(*) AS n FROM items;`).one().n).toBe(100001);
      backup.release({backupId: generation}); config.BACKUP_MODE = 'export';
      backup.freeze({backupId: 'scale-recovered-export', mode: 'export'});
      const actual: string[] = []; let afterRowId: number | undefined;
      do {
        const page = backup.exportPage({backupId: 'scale-recovered-export', table: 'items', afterRowId});
        actual.push(page.digest); afterRowId = page.nextRowId ?? undefined;
      } while (afterRowId !== undefined);
      expect(actual).toEqual(expected);
    });
  }, 120_000);
});
