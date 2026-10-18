#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Read-only metadata load test. Token contents and API response bodies are never logged.
import { readFileSync, writeFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';

const args = {};
for (let i = 2; i < process.argv.length; i += 2) args[process.argv[i]] = process.argv[i + 1];
const required = ['--origin', '--filespace', '--token-file', '--output'];
if (required.some(key => !args[key])) {
  console.error('Usage: node scripts/benchmark-server.mjs --origin URL --filespace ID --token-file PATH --output PATH [--requests 1000] [--concurrency 16]');
  process.exit(2);
}
const count = Number(args['--requests'] ?? 1000);
const concurrency = Number(args['--concurrency'] ?? 16);
if (!Number.isSafeInteger(count) || count < 1 || count > 100000 || !Number.isSafeInteger(concurrency) || concurrency < 1 || concurrency > 128) throw new Error('Invalid request count or concurrency.');
const base = new URL(args['--origin']);
if (base.username || base.password || base.search || base.hash || base.pathname !== '/') throw new Error('Use an origin without credentials or a path.');
const token = readFileSync(args['--token-file'], 'utf8').trim();
const prefix = `/v1/filespaces/${encodeURIComponent(args['--filespace'])}`;
const routes = [`${prefix}/items?parent=root&limit=200`, `${prefix}/changes?since=0&limit=200`];
const samples = [];
const statuses = {};
let next = 0;
let responseBytes = 0;
const start = performance.now();
await Promise.all(Array.from({ length: Math.min(count, concurrency) }, async () => {
  while (next < count) {
    const index = next++;
    const began = performance.now();
    let status = 'network_error';
    try {
      const response = await fetch(new URL(routes[index % routes.length], base), {
        headers: { authorization: `Bearer ${token}` }, redirect: 'error', signal: AbortSignal.timeout(30000),
      });
      status = String(response.status);
      const body = await response.arrayBuffer();
      responseBytes += body.byteLength;
      if (response.status === 200 && !(response.headers.get('content-type') || '').includes('application/json')) status = 'invalid_response';
    } catch { /* Record failed requests without leaking credentials or upstream URLs. */ }
    statuses[status] = (statuses[status] || 0) + 1;
    samples.push(performance.now() - began);
  }
}));
const elapsedSeconds = (performance.now() - start) / 1000;
samples.sort((a, b) => a - b);
const percentile = p => Math.round(samples[Math.min(samples.length - 1, Math.ceil(samples.length * p) - 1)] * 100) / 100;
const report = {
  measuredAt: new Date().toISOString(), origin: base.origin, workload: 'directory listing and change feed, up to 200 entries each',
  requests: count, concurrency, elapsedSeconds, requestsPerSecond: count / elapsedSeconds,
  latencyMs: { p50: percentile(0.5), p95: percentile(0.95), p99: percentile(0.99) },
  statuses, responseBytes, ok: statuses['200'] === count,
};
writeFileSync(args['--output'], JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
console.log(JSON.stringify(report, null, 2));
if (!report.ok) process.exitCode = 1;
