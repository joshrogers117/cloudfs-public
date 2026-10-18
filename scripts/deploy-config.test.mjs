// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseVars, productionVars, productionR2Bindings, productionEmailBindings, validateSecrets } from './deploy-config.mjs';
const valid = { CLOUDFLARE_ACCOUNT_ID: 'a'.repeat(32), S3_BUCKET: 'team-data', PUBLIC_BASE_URL: 'https://cloudfs.team.test' };
test('derives R2 and same-origin defaults; signup is closed', () => {
 const actual = productionVars(valid);
 assert.equal(actual.S3_ENDPOINT, `https://${'a'.repeat(32)}.r2.cloudflarestorage.com`);
 assert.equal(actual.WEB_BASE_URL, actual.PUBLIC_BASE_URL);
 assert.equal(actual.SIGNUP_MODE, 'closed');
 assert.equal(actual.DATA_BUCKET_ENDPOINT, actual.S3_ENDPOINT);
 assert.equal(actual.DATA_BUCKET_NAME, actual.S3_BUCKET);
});
test('native verification binding matches only the deployment account and preserves other bindings', () => {
 const existing = [{binding:'AUDIT_BUCKET',bucket_name:'old-audit'},{binding:'CUSTOM_BUCKET',bucket_name:'custom'},
  {binding:'DATA_BUCKET',bucket_name:'old-data'}];
 const actual = productionVars({...valid,CLOUDFS_AUDIT_BUCKET:'new-audit'});
 assert.deepEqual(productionR2Bindings(actual,existing),[
  {binding:'CUSTOM_BUCKET',bucket_name:'custom'}, {binding:'AUDIT_BUCKET',bucket_name:'new-audit'},
  {binding:'DATA_BUCKET',bucket_name:'team-data'},
 ]);
 for(const S3_ENDPOINT of ['https://s3.us-east-1.amazonaws.com',`https://${'b'.repeat(32)}.r2.cloudflarestorage.com`]) {
  const external=productionVars({...valid,S3_ENDPOINT});
  assert.equal(external.DATA_BUCKET_ENDPOINT,undefined);
  assert.equal(external.DATA_BUCKET_NAME,undefined);
  assert.deepEqual(productionR2Bindings(external,existing),existing.slice(0,2));
 }
 for(const patch of [{DATA_BUCKET_NAME:'wrong'}, {DATA_BUCKET_ENDPOINT:'https://wrong.test',DATA_BUCKET_NAME:'team-data'},
  {S3_ENDPOINT:'https://s3.us-east-1.amazonaws.com',DATA_BUCKET_NAME:'team-data',DATA_BUCKET_ENDPOINT:'https://s3.us-east-1.amazonaws.com'}]) {
  assert.throws(()=>productionVars({...valid,...patch}),/DATA_BUCKET mapping/);
 }
});
test('never sources shell substitutions or accepts secrets among public vars', () => {
 assert.throws(() => parseVars('S3_BUCKET=$(touch /tmp/not-run)'), /literal/);
 assert.throws(() => parseVars('AUTH_SIGNING_SECRET=secret'), /secrets file/);
 assert.throws(() => parseVars('RESEND_API_KEY=secret'), /secrets file/);
 assert.throws(() => parseVars('X=a\nX=b'), /Duplicate/);
 assert.deepEqual(parseVars('# harmless\nS3_BUCKET="my-bucket"'), {S3_BUCKET:'my-bucket'});
});
test('rejects placeholders and unsafe public origins before any deploy', () => {
 for (const patch of [{S3_BUCKET:'CHANGE-ME'}, {PUBLIC_BASE_URL:'http://127.0.0.1:8787'}, {S3_ENDPOINT:'https://user:password@bucket.test'}, {PUBLIC_BASE_URL:'https://your-gateway.example.com'}, {SIGNUP_MODE:'open'}]) {
  assert.throws(() => productionVars({...valid, ...patch}));
 }
});
test('validates required secrets and encryption-key length', () => {
 const s = { AUTH_SIGNING_SECRET:'a'.repeat(64),BOOTSTRAP_SECRET:'b'.repeat(64),STORAGE_ENC_KEY:Buffer.alloc(32,1).toString('base64'),S3_ACCESS_KEY_ID:'test-id',S3_SECRET_ACCESS_KEY:'test-secret' };
 assert.doesNotThrow(() => validateSecrets(s));
 assert.throws(() => validateSecrets({...s,S3_SECRET_ACCESS_KEY:''}), /Fill/);
 assert.throws(() => validateSecrets({...s,STORAGE_ENC_KEY:'short'}), /32 random bytes/);
});
test('production cannot disable object verification or log recovery links', () => {
 assert.equal(productionVars(valid).STORAGE_VERIFY_UPLOADS, '1');
 assert.throws(() => productionVars({...valid, STORAGE_VERIFY_UPLOADS:'0'}), /verification/);
 assert.throws(() => productionVars({...valid, EMAIL_PROVIDER:'console'}), /private email/);
 assert.throws(() => productionVars({...valid, EMAIL_PROVIDER:' Console '}), /private email/);
 assert.equal(productionVars({...valid, EMAIL_PROVIDER:' CloudFlare '}).EMAIL_PROVIDER, 'cloudflare');
 assert.throws(() => productionVars({...valid, EMAIL_DEV_CONSOLE:'true'}), /private email/);
});

test('email binding is scoped to this deployment sender and preserves unrelated bindings', () => {
 const old = [{name:'EMAIL',allowed_sender_addresses:['old@old.test']},{name:'ALERTS'}];
 assert.deepEqual(productionEmailBindings({},old),[{name:'ALERTS'}]);
 assert.deepEqual(productionEmailBindings({EMAIL_FROM:'trial@team.test',EMAIL_PROVIDER:'cloudflare'},old),[
  {name:'ALERTS'},{name:'EMAIL',allowed_sender_addresses:['trial@team.test']},
 ]);
 assert.deepEqual(productionEmailBindings({EMAIL_FROM:'trial@team.test'}),[
  {name:'EMAIL',allowed_sender_addresses:['trial@team.test']},
 ]);
 assert.deepEqual(productionEmailBindings({EMAIL_FROM:'trial@team.test',EMAIL_PROVIDER:'resend'},old),[{name:'ALERTS'}]);
 assert.throws(()=>productionEmailBindings({EMAIL_PROVIDER:'cloudflare'}),/EMAIL_FROM/);
 assert.throws(()=>productionEmailBindings({EMAIL_FROM:'Name <trial@team.test>'}),/plain sender/);
});
