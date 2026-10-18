// SPDX-License-Identifier: AGPL-3.0-or-later
import { env, runInDurableObject } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { NamespaceStore } from '../src/metadata/namespace';
import { SnapshotStore } from '../src/metadata/snapshots';
import { filespaceDoName } from '../src/security/auth';
import { DoAclStore } from '../src/metadata/acl-store';
import type { Env } from '../src/env';

async function stores(fn: (sql: SqlStorage, ns: NamespaceStore, snapshots: SnapshotStore) => void) {
  const e = env as Env;
  const stub = e.FILESPACE.get(e.FILESPACE.idFromName(filespaceDoName('snapshot-streams', crypto.randomUUID())));
  await runInDurableObject(stub, (_instance, state) => {
    const ns = new NamespaceStore(state.storage.sql);
    fn(state.storage.sql, ns, new SnapshotStore(state.storage.sql, () => ns.currentSeq(), ns));
  });
}
const old = new Uint8Array([1, 2, 3, 4]), newer = new Uint8Array([9, 8]);
const seed = (ns: NamespaceStore) => {
  ns.put(null, 'root', true, 0, { id: 'root' });
  ns.put('root', 'Shared', true, 0, { id: 'shared' });
  ns.put('shared', 'clip.mov', false, 0, { id: 'clip' });
  ns.putStream('clip', 'AFP_Resource', old, 4);
  ns.putStream('clip', 'AFP_AfpInfo', new Uint8Array(60).fill(3), 60);
};
describe('immutable Mac metadata in snapshots', () => {
  it('retains encrypted streams after live overwrite/delete and base snapshot deletion', async () => {
    await stores((sql, ns, snapshots) => {
      seed(ns);
      snapshots.create({ id: 's1', scope: 'shared' });
      snapshots.create({ id: 's2', scope: 'shared' });
      expect(Number(sql.exec(`SELECT COUNT(*) AS n FROM snapshot_streams WHERE snapshot_id='s2'`).one().n)).toBe(0);
      ns.putStream('clip', 'AFP_Resource', newer, 2);
      ns.deleteStream('clip', 'AFP_AfpInfo');
      snapshots.create({ id: 's3', scope: 'shared' });
      expect(snapshots.streamAt('s1', 'clip', 'AFP_Resource')).toEqual(old);
      expect(snapshots.streamAt('s2', 'clip', 'AFP_AfpInfo')).toEqual(new Uint8Array(60).fill(3));
      expect(snapshots.streamAt('s3', 'clip', 'AFP_Resource')).toEqual(newer);
      expect(snapshots.streamAt('s3', 'clip', 'AFP_AfpInfo')).toBeNull();
      snapshots.deleteSnapshot('s1');
      expect(snapshots.streamAt('s2', 'clip', 'AFP_Resource')).toEqual(old);
      expect(snapshots.itemAt('s2', 'clip')?.rsrcForkSize).toBe(4);
      snapshots.deleteSnapshot('s2');
      expect(snapshots.streamAt('s3', 'clip', 'AFP_Resource')).toEqual(newer);
      expect(Number(sql.exec(`SELECT COUNT(*) AS n FROM snapshot_streams WHERE snapshot_id IN ('s1','s2')`).one().n)).toBe(0);
    });
  });
  it('restores exact stream set atomically with content, including removal of newer streams', async () => {
    await stores((_sql, ns, snapshots) => {
      seed(ns); snapshots.create({ id: 'before', scope: 'shared' });
      ns.putStream('clip', 'AFP_Resource', newer, 2);
      ns.putStream('clip', 'new-only', newer, 2);
      const result = snapshots.restore('before', 'clip');
      expect(result.restored).toEqual(['clip']);
      expect(ns.getStream('clip', 'AFP_Resource')).toEqual(old);
      expect(ns.getStream('clip', 'AFP_AfpInfo')).toEqual(new Uint8Array(60).fill(3));
      expect(ns.getStream('clip', 'new-only')).toBeNull();
      ns.remove('clip'); snapshots.restore('before', 'clip');
      expect(ns.getStream('clip', 'AFP_Resource')).toEqual(old);
    });
  });
  it('new snapshots do not inherit missing metadata from pre-upgrade snapshots', async () => {
    await stores((sql, ns, snapshots) => {
      seed(ns); snapshots.create({ id: 'legacy', scope: 'shared' });
      sql.exec(`UPDATE snapshots SET streams_captured=0 WHERE id='legacy'`);
      sql.exec(`DELETE FROM snapshot_streams WHERE snapshot_id='legacy'`);
      snapshots.create({ id: 'complete', scope: 'shared' });
      expect(snapshots.streamsCaptured('legacy')).toBe(false);
      expect(snapshots.streamsCaptured('complete')).toBe(true);
      expect(snapshots.streamAt('complete', 'clip', 'AFP_Resource')).toEqual(old);
      expect(sql.exec(`SELECT base_snapshot_id FROM snapshots WHERE id='complete'`).one().base_snapshot_id).toBeNull();
    });
  });
});
