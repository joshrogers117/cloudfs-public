// SPDX-License-Identifier: AGPL-3.0-or-later
import {env,runInDurableObject} from 'cloudflare:test';
import {describe,it,expect} from 'vitest';
import {BackupState} from '../src/backup-state';
import type {Env} from '../src/env';

async function directoryTest(body:(helper:BackupState,state:DurableObjectState)=>void) {
  const stub=(env as Env).DIRECTORY_DO.getByName(`backup-generation-review-${crypto.randomUUID()}`);
  return runInDurableObject(stub,(_instance,state)=>{
    const helper=new BackupState(state.storage,{BACKUP_MODE:'export'},'directory');helper.initialize();body(helper,state);
  });
}

describe('independent durable backup generation lifecycle',()=>{
  it('cancels an export target that never froze, preventing a delayed freeze from resurrecting it',async()=>{
    await directoryTest((helper,state)=>{
      expect(()=>helper.release({backupId:'export_canceled_before_freeze'})).not.toThrow();
      expect(()=>helper.freeze({backupId:'export_canceled_before_freeze',mode:'export'})).toThrow(/generation_released/);
      const normal=new BackupState(state.storage,{},'directory');normal.initialize();expect(()=>normal.assertOrdinary()).not.toThrow();
      expect(()=>helper.freeze({backupId:'export_fresh_generation',mode:'export'})).not.toThrow();
    });
  });
  it('keeps a newer durable hold when a previous canceled export releases again',async()=>{
    await directoryTest((helper,state)=>{
      helper.freeze({backupId:'export_generation_A',mode:'export'});helper.release({backupId:'export_generation_A'});
      helper.freeze({backupId:'export_generation_B',mode:'export'});helper.release({backupId:'export_generation_A'});
      const normal=new BackupState(state.storage,{},'directory');normal.initialize();expect(()=>normal.assertOrdinary()).toThrow(/maintenance/);
      expect(()=>helper.freeze({backupId:'export_generation_C',mode:'export'})).toThrow(/already_frozen/);
      helper.release({backupId:'export_generation_B'});
      expect(()=>helper.freeze({backupId:'export_generation_A',mode:'export'})).toThrow(/generation_released/);
    });
  });
  it('rejects a delayed coordinator update after two successive exports finished',async()=>{
    await directoryTest(helper=>{
      const put=(backupId:string,phase:string,revision:number,expectedRevision:number,expectedPreviousBackupId?:string)=>helper.coordinatorSet({backupId,state:{backupId,phase,revision},expectedRevision,expectedPreviousBackupId});
      put('export_generation_A','freezing',1,0);put('export_generation_A','aborted',2,1);
      put('export_generation_B','freezing',1,0,'export_generation_A');put('export_generation_B','complete',2,1);
      expect(()=>put('export_generation_A','exporting',2,1)).toThrow();
      expect(helper.coordinatorGet()).toMatchObject({backupId:'export_generation_B',phase:'complete'});
    });
  });
});
