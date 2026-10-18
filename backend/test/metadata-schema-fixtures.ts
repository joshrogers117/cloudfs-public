// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Restore the locks table shape that existed before migration 30 when a test
 * intentionally rewinds migration history on a current Durable Object fixture.
 * Keeping migration history and the relevant table shape in sync ensures the
 * v30 ALTER TABLE runs against a genuine v29 locks schema.
 */
export function restorePreV30LocksTable(sql: SqlStorage): void {
  sql.exec(`CREATE TABLE locks_pre_v30 (
    path TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'exclusive',
    fence INTEGER NOT NULL,
    acquired_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );`);
  sql.exec(`INSERT INTO locks_pre_v30(path,owner,mode,fence,acquired_at,expires_at)
    SELECT path,owner,mode,fence,acquired_at,expires_at FROM locks;`);
  sql.exec('DROP TABLE locks;');
  sql.exec('ALTER TABLE locks_pre_v30 RENAME TO locks;');
  sql.exec('CREATE INDEX locks_expiry ON locks(expires_at);');
}
