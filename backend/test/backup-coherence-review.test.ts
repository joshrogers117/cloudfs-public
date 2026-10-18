// SPDX-License-Identifier: AGPL-3.0-or-later
import {env,runInDurableObject} from 'cloudflare:test';
import {describe,it,expect} from 'vitest';
import {BackupState,backupPageDigest,type BackupKind} from '../src/backup-state';
import {validateBackupCoherence} from '../src/backup-coherence';
import type {Env} from '../src/env';

async function realFixture() {
  const fixtureId=crypto.randomUUID(),backupId=`backup_${fixtureId}`,orgId='team';
  const configured=env as Env;
  const real:any={directory:configured.DIRECTORY_DO.getByName(`review-${fixtureId}`),org:configured.ORG_DO.getByName(`review-${fixtureId}`),auth:configured.AUTH_DO.getByName(`review-${fixtureId}`)};
  const sql=async(kind:string,query:string,...values:any[])=>runInDurableObject(real[kind],(_instance,state)=>{state.storage.sql.exec(query,...values);});
  await sql('org',`INSERT INTO users(id,org_id,email,display_name,role,kind,status,created_at) VALUES('member','team','member@test','Member','owner','human','active',1);`);
  await sql('auth',`INSERT INTO accounts(id,user_id,org_id,email,display_name,role,status,email_verified,created_at) VALUES('account','member','team','member@test','Member','owner','active',1,1);`);
  await sql('auth',`INSERT INTO webauthn_creds(id,account_id,credential_id,public_key,transports,created_at) VALUES('credential-row','account','credential','public-key','[]',1);`);
  await sql('directory',`INSERT INTO email_index(email_lower,org_id,account_id,created_at) VALUES('member@test','team','account',1);`);
  await sql('directory',`INSERT INTO webauthn_index(credential_id,org_id,account_id,created_at) VALUES('credential','team','account',1);`);
  for(const kind of ['directory','org','auth'] as BackupKind[]) await runInDurableObject(real[kind],(instance,state)=>{
    const helper=new BackupState(state.storage,{BACKUP_MODE:'export'},kind);helper.initialize();helper.freeze({backupId,mode:'export'});(instance as any).reviewHelper=helper;
  });
  const namespace=(kind:string)=>({idFromName:(name:string)=>name,get:()=>({
    backupCatalogPage:(input:any)=>runInDurableObject(real[kind],instance=>(instance as any).reviewHelper.catalogPage(input)),
    backupCheckReferences:(input:any)=>runInDurableObject(real[kind],instance=>(instance as any).reviewHelper.checkReferences(input)),
  })});
  const e={...env,DIRECTORY_DO:namespace('directory'),ORG_DO:namespace('org'),AUTH_DO:namespace('auth')} as unknown as Env;
  const session={backupId,organizations:[orgId],targets:[{id:'directory:global',kind:'directory' as const,name:'global'},...(['org','auth'] as const).map(kind=>({id:`${kind}:team`,kind,name:'team',orgId}))]};
  return {e,session,sql};
}

describe('independent cross-authority backup coherence',()=>{
  it('accepts a consistent real SQLite account, membership and passkey directory graph',async()=>{
    const f=await realFixture();await expect(validateBackupCoherence(f.e,f.session)).resolves.toBeUndefined();
  });
  it('refuses a directory email claim captured before its account creation committed',async()=>{
    const f=await realFixture();await f.sql('auth',`DELETE FROM accounts WHERE id='account';`);
    await expect(validateBackupCoherence(f.e,f.session)).rejects.toThrow();
  });
  it('refuses a passkey directory claim whose actual credential is missing',async()=>{
    const f=await realFixture();await f.sql('auth',`DELETE FROM webauthn_creds WHERE credential_id='credential';`);
    await expect(validateBackupCoherence(f.e,f.session)).rejects.toThrow();
  });
  it('refuses a valid account whose organization membership is missing',async()=>{
    const f=await realFixture();await f.sql('org',`DELETE FROM users WHERE id='member';`);
    await expect(validateBackupCoherence(f.e,f.session)).rejects.toThrow();
  });
  it('refuses the partially changed email identity even when both IDs still exist',async()=>{
    const f=await realFixture();await f.sql('auth',`UPDATE accounts SET email='new@test' WHERE id='account';`);
    await expect(validateBackupCoherence(f.e,f.session)).rejects.toThrow();
  });
  it('bounds reference calls and does not stop at the first catalog page',async()=>{
    const seen:any[]=[],pages:any[]=[],backupId='bounded_fixture';
    const makePage=(table:string,rows:string[][],nextRowId:number|null)=>{const value={table,columns:table==='email_index'?['email_lower','org_id','account_id']:[],rows:rows.map(row=>row.map(value=>({type:'text' as const,value}))),nextRowId};return {...value,digest:backupPageDigest(value)};};
    const directory={backupCatalogPage:async(input:any)=>{pages.push(input);if(input.table!=='email_index')return makePage(input.table,[],null);const offset=input.afterRowId??0;return makePage('email_index',Array.from({length:offset===0?257:1},(_,i)=>[`email${offset+i}@test`,'team',`account${offset+i}`]),offset===0?257:null);}};
    const auth={backupCatalogPage:async(input:any)=>makePage(input.table,[],null),backupCheckReferences:async(input:any)=>{seen.push(input.references);}};
    const ns=(value:any)=>({idFromName:(v:string)=>v,get:()=>value});
    const e={...env,DIRECTORY_DO:ns(directory),AUTH_DO:ns(auth),ORG_DO:ns({})} as unknown as Env;
    await validateBackupCoherence(e,{backupId,organizations:['team'],targets:[{id:'directory:global',name:'global',kind:'directory'},{id:'auth:team',name:'team',kind:'auth',orgId:'team'},{id:'org:team',name:'team',kind:'org',orgId:'team'}]});
    expect(seen.map(batch=>batch.length)).toEqual([128,128,1,1]);
    expect(seen.flat().at(-1).match.id).toBe('account257');expect(pages.some(input=>input.afterRowId===257)).toBe(true);
  });
});
