// SPDX-License-Identifier: AGPL-3.0-or-later
export const RECLAMATION_GRACE_MS = 7 * 24 * 60 * 60 * 1000;
export const RECLAMATION_BATCH = 64;
const eligible = `b.refcount<=0 AND b.unreferenced_at IS NOT NULL AND b.unreferenced_at<=?1
  AND NOT EXISTS(SELECT 1 FROM retained_blocks r WHERE r.block_hash=b.block_hash)
  AND NOT EXISTS(SELECT 1 FROM blocks r WHERE r.object_key=b.object_key)
  AND NOT EXISTS(SELECT 1 FROM stream_blocks r WHERE r.object_key=b.object_key)
  AND NOT EXISTS(SELECT 1 FROM snapshot_blocks r WHERE r.object_key=b.object_key)
  AND NOT EXISTS(SELECT 1 FROM snapshot_stream_blocks r WHERE r.object_key=b.object_key)
  AND NOT EXISTS(SELECT 1 FROM block_upload_claims c WHERE c.object_key=b.object_key)
  AND NOT EXISTS(SELECT 1 FROM uploads u WHERE u.key=b.object_key AND u.state='in_progress')`;
export type ReclamationTicket = { key: string; token: string };
/** No retention timer silently retires a client's recovery dependencies. An
 * operator supplies the timestamp through which all pending client recovery has
 * been reconciled. Live retained history and all upload claims remain roots. */
export class ReclamationStore {
  constructor(private readonly sql: SqlStorage) {}
  report(recoveredThrough=Date.now()) {
    const totals=this.sql.exec(`SELECT COUNT(*) AS objects,COALESCE(SUM((SELECT MAX(v.ciphertext_size) FROM verified_objects v WHERE v.object_key=b.object_key)),0) AS verified_bytes
      FROM block_refs b WHERE ${eligible};`,recoveredThrough).one();
    const states=this.sql.exec('SELECT state,COUNT(*) AS objects FROM object_reclamation GROUP BY state;').toArray();
    const failures=this.sql.exec("SELECT object_key,attempts,last_error,next_at FROM object_reclamation WHERE last_error IS NOT NULL ORDER BY next_at LIMIT 64;").toArray();
    return {candidateObjects:Number(totals.objects),candidateVerifiedBytes:Number(totals.verified_bytes),states,failures,graceMs:RECLAMATION_GRACE_MS};
  }
  quarantine(recoveredThrough: number, now=Date.now()): number {
    if (!Number.isSafeInteger(recoveredThrough) || recoveredThrough<0 || recoveredThrough>now) throw new Error('invalid_recovery_watermark');
    const candidates=this.sql.exec(`SELECT b.object_key FROM block_refs b WHERE ${eligible}
      AND NOT EXISTS(SELECT 1 FROM object_reclamation q WHERE q.object_key=b.object_key)
      ORDER BY b.unreferenced_at,b.object_key LIMIT ${RECLAMATION_BATCH};`,recoveredThrough).toArray();
    for (const row of candidates) this.sql.exec(`INSERT INTO object_reclamation(object_key,token,state,recovered_through,next_at,attempts)
      VALUES(?,?,'quarantined',?,?,0);`,row.object_key,crypto.randomUUID(),recoveredThrough,now+RECLAMATION_GRACE_MS);
    return candidates.length;
  }
  due(now=Date.now()): ReclamationTicket[] {
    return this.sql.exec(`SELECT object_key,token FROM object_reclamation WHERE next_at<=? ORDER BY next_at LIMIT ${RECLAMATION_BATCH};`,now).toArray()
      .map(r=>({key:String(r.object_key),token:String(r.token)}));
  }
  nextDue(): number | null {
    const row=this.sql.exec('SELECT MIN(next_at) AS at FROM object_reclamation;').one();return row.at===null?null:Number(row.at);
  }
  /** Must commit before external I/O. Publication triggers refuse a deleting or
   * deleted key forever, including late uploads and a lost delete response. */
  begin(ticket:ReclamationTicket,now=Date.now()):boolean {
    const row=this.sql.exec('SELECT * FROM object_reclamation WHERE object_key=? AND token=?;',ticket.key,ticket.token).toArray()[0];
    if (!row || Number(row.next_at)>now) return false;
    if (row.state==='quarantined') {
      const still=this.sql.exec(`SELECT 1 FROM block_refs b WHERE ${eligible} AND b.object_key=?2;`,row.recovered_through,ticket.key).toArray().length>0;
      if (!still) {this.sql.exec('DELETE FROM object_reclamation WHERE object_key=? AND token=?;',ticket.key,ticket.token);return false;}
    }
    this.sql.exec("UPDATE object_reclamation SET state='deleting',attempts=attempts+1,next_at=? WHERE object_key=? AND token=?;",now+60_000,ticket.key,ticket.token);
    return true;
  }
  finish(ticket:ReclamationTicket,success:boolean,now=Date.now()):void {
    const row=this.sql.exec("SELECT attempts FROM object_reclamation WHERE object_key=? AND token=? AND state='deleting';",ticket.key,ticket.token).toArray()[0];
    if (!row) return;
    if (success) {
      this.sql.exec('DELETE FROM verified_objects WHERE object_key=?;',ticket.key);
      this.sql.exec('DELETE FROM block_refs WHERE object_key=? AND refcount<=0;',ticket.key);
      // Keep a compact permanent tombstone. Periodic re-deletion covers a PUT
      // admitted before quarantine whose completion was delayed/unknown.
      this.sql.exec("UPDATE object_reclamation SET state='deleted',last_error=NULL,attempts=0,next_at=? WHERE object_key=? AND token=?;",now+30*24*60*60*1000,ticket.key,ticket.token);
    } else {
      const delay=Math.min(24*60*60*1000,60_000*2**Math.min(10,Number(row.attempts)));
      this.sql.exec("UPDATE object_reclamation SET last_error='storage_delete_failed',next_at=? WHERE object_key=? AND token=?;",now+delay,ticket.key,ticket.token);
    }
  }
}
