// End-to-end data-path proof (no File Provider mount, no Cloudflare account):
//   admin: create bucket + upload a block to local MinIO
//   SigV4 presign (the SAME aws4fetch the gateway's presign.ts uses): mint a presigned
//     GET URL for that block
//   client: fetch a BYTE RANGE via that presigned URL → expect HTTP 206 + correct bytes
// This exercises the exact read path the macOS engine will use, against a real S3 server.
//
// NOTE: the presign step is done CLIENT-SIDE here (identical SigV4 to the gateway's
// presign.ts) rather than via the gateway route, because that route is now ACL-gated and
// requires a bootstrapped org/space + a signed token (the old `Bearer dev-token` bypass
// was retired). The byte-range path proven below is identical either way.
//
// Prereqs:  MinIO on :9000 (creds localdev/localdevsecret).
// Run:      node tools/dataplane-demo.mjs           (from the backend/ dir)
import { AwsClient } from "aws4fetch";

const S3 = "http://127.0.0.1:9000";
const BUCKET = "cloudfs";
const KEY = "chunks/te/test-block";
const SIZE = 16 * 1024 * 1024; // 16 MiB "block"
const RANGE_LEN = 1024 * 1024; // read first 1 MiB

const aws = new AwsClient({ accessKeyId: "localdev", secretAccessKey: "localdevsecret", region: "auto", service: "s3" });
const ok = (b) => (b ? "✅" : "❌");

async function main() {
  // 1. bucket
  let r = await aws.fetch(`${S3}/${BUCKET}`, { method: "PUT" });
  console.log(`create bucket: HTTP ${r.status} ${ok(r.status === 200 || r.status === 409)}`);

  // 2. upload a deterministic 16 MiB block (byte i = i % 251, prime → easy to verify any offset)
  const data = new Uint8Array(SIZE);
  for (let i = 0; i < SIZE; i++) data[i] = i % 251;
  r = await aws.fetch(`${S3}/${BUCKET}/${KEY}`, { method: "PUT", body: data });
  console.log(`upload ${SIZE / 1048576} MiB block: HTTP ${r.status} ${ok(r.ok)}`);

  // 3. mint a presigned GET URL with SigV4 (aws4fetch query-signing — the SAME path
  //    presign.ts uses inside the gateway). `signQuery:true` moves the signature into
  //    the query string so a plain client can stream the bytes with no auth header.
  const signed = await aws.sign(
    new Request(`${S3}/${BUCKET}/${KEY}?X-Amz-Expires=300`, { method: "GET" }),
    { aws: { signQuery: true } },
  );
  const url = signed.url;
  console.log(`presigned URL (SigV4 query-signed): ${ok(!!url && url.includes("X-Amz-Signature"))}`);

  // 4. client fetches a BYTE RANGE directly from MinIO via the presigned URL
  const t0 = performance.now();
  const rg = await fetch(url, { headers: { Range: `bytes=0-${RANGE_LEN - 1}` } });
  const body = new Uint8Array(await rg.arrayBuffer());
  const ms = (performance.now() - t0).toFixed(1);
  console.log(`range GET [0..${RANGE_LEN - 1}]: HTTP ${rg.status} ${ok(rg.status === 206)} | got ${body.length} bytes in ${ms} ms`);

  // 5. verify the bytes are exactly what we uploaded for that range
  let correct = body.length === RANGE_LEN;
  for (let i = 0; correct && i < body.length; i++) if (body[i] !== i % 251) correct = false;
  console.log(`bytes match expected for the range: ${ok(correct)}`);

  // 6. a middle range too (proves arbitrary offsets, not just from 0)
  const off = 10 * 1024 * 1024;
  const rg2 = await fetch(url, { headers: { Range: `bytes=${off}-${off + 0xffff}` } });
  const b2 = new Uint8Array(await rg2.arrayBuffer());
  let c2 = b2.length === 65536;
  for (let i = 0; c2 && i < b2.length; i++) if (b2[i] !== (off + i) % 251) c2 = false;
  console.log(`mid-range GET [${off}..]: HTTP ${rg2.status} ${ok(rg2.status === 206)} | bytes match ${ok(c2)}`);

  const allGood = rg.status === 206 && correct && rg2.status === 206 && c2;
  console.log(`\nDATA PATH ${allGood ? "WORKS ✅  (SigV4 presign → MinIO byte-range stream)" : "FAILED ❌"}`);
  process.exit(allGood ? 0 : 1);
}
main().catch((e) => { console.error("error:", e.message); process.exit(1); });
