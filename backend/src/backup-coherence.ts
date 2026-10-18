// SPDX-License-Identifier: AGPL-3.0-or-later
// A freeze is per authority, not a distributed transaction. Reject the concrete
// dangling cross-authority edges left by an interrupted provisioning saga.
import type { Env } from './env';
import { backupPageDigest, type BackupPage } from './backup-state';

type Kind = 'directory' | 'org' | 'auth' | 'filespace';
interface Target { id: string; kind: Kind; name: string; orgId?: string }
interface Session { backupId: string; organizations: string[]; targets: Target[] }
interface Reference { table: string; match: Record<string,string> }
interface CatalogStub {
  backupCatalogPage(input: {backupId: string; table: string; afterRowId?: number}): Promise<BackupPage>;
  backupCheckReferences(input: {backupId: string; references: Reference[]}): Promise<unknown>;
}
const MAX_REFERENCES = 128;
function fail(): never { throw new Error('backup_cross_authority_catalog_mismatch'); }
function authority(env: Env, target: Target): CatalogStub {
  const namespace = target.kind === 'directory' ? env.DIRECTORY_DO : target.kind === 'org' ? env.ORG_DO : env.AUTH_DO;
  return namespace.get(namespace.idFromName(target.name)) as unknown as CatalogStub;
}
function textRow(page: BackupPage, rowIndex: number): Record<string,string> {
  const cells = page.rows[rowIndex];
  if (!Array.isArray(cells) || cells.length !== page.columns.length) fail();
  const row: Record<string,string> = Object.create(null);
  for (let i=0;i<cells.length;i++) if (cells[i].type === 'text') row[page.columns[i]] = (cells[i] as {type:'text';value:string}).value;
  return row;
}
function required(row: Record<string,string>, name: string): string {
  if (typeof row[name] !== 'string' || !row[name]) fail();
  return row[name];
}
/** All source/staged rows stay in their owning DO. At most one bounded page and
 * 128 small point references are held here, regardless of deployment size. */
export async function validateBackupCoherence(env: Env, session: Session): Promise<void> {
  const directory = session.targets.find(target=>target.kind === 'directory');
  if (!directory) fail();
  const targetFor = (kind: Kind, orgId: string): Target => {
    if (!session.organizations.includes(orgId)) fail();
    const target = session.targets.find(value=>value.kind===kind && value.orgId===orgId);
    return target ?? fail();
  };
  const validateRows = async (source: Target, table: string, destination: (row: Record<string,string>)=>{target:Target;reference:Reference}) => {
    let cursor: number | undefined;
    while (true) {
      const page = await authority(env,source).backupCatalogPage({backupId:session.backupId,table,afterRowId:cursor});
      if (page.table!==table || !Array.isArray(page.columns) || !Array.isArray(page.rows) || page.rows.length>4096
          || new Set(page.columns).size!==page.columns.length || backupPageDigest(page)!==page.digest) fail();
      // Group only this bounded page, flushing each target at 128 references.
      const batches = new Map<string,{target:Target;references:Reference[]}>();
      const check = async (batch:{target:Target;references:Reference[]}) => {
        if (!batch.references.length) return;
        await authority(env,batch.target).backupCheckReferences({backupId:session.backupId,references:batch.references});
        batch.references=[];
      };
      for (let index=0;index<page.rows.length;index++) {
        const item=destination(textRow(page,index));
        let batch=batches.get(item.target.id);
        if (!batch) { batch={target:item.target,references:[]};batches.set(item.target.id,batch); }
        batch.references.push(item.reference);
        if (batch.references.length===MAX_REFERENCES) await check(batch);
      }
      for (const batch of batches.values()) await check(batch);
      if (page.nextRowId===null) return;
      if (!Number.isSafeInteger(page.nextRowId) || page.nextRowId <= (cursor ?? -1) || !page.rows.length) fail();
      cursor=page.nextRowId;
    }
  };
  await validateRows(directory,'email_index',row=>{
    const orgId=required(row,'org_id');
    return {target:targetFor('auth',orgId),reference:{table:'accounts',match:{id:required(row,'account_id'),org_id:orgId,email:required(row,'email_lower')}}};
  });
  await validateRows(directory,'webauthn_index',row=>({
    target:targetFor('auth',required(row,'org_id')),
    reference:{table:'webauthn_creds',match:{credential_id:required(row,'credential_id'),account_id:required(row,'account_id')}},
  }));
  for (const source of session.targets.filter(target=>target.kind==='auth')) await validateRows(source,'accounts',row=>{
    const orgId=required(row,'org_id');
    if (source.orgId!==orgId) fail();
    return {target:targetFor('org',orgId),reference:{table:'users',match:{id:required(row,'user_id'),org_id:orgId,email:required(row,'email')}}};
  });
}
