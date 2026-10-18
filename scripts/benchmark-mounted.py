#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Measure the real encrypted SMB path against an existing test filespace.

Creates one uniquely named remote file and leaves it there for inspection,
or re-reads a named fixture with a supplied size and SHA-256.
The bearer token is read from CLOUDFS_BENCHMARK_TOKEN, never command arguments.
"""
import argparse
import hashlib
import json
import os
import re
import random
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import tempfile
import time
import urllib.parse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gateway', required=True, help='HTTPS gateway (loopback HTTP also allowed)')
    parser.add_argument('--filespace', required=True, help='Test filespace ID (writable unless --read-existing is used)')
    parser.add_argument('--daemon', required=True, type=Path, help='Release cloudfsd executable')
    parser.add_argument('--key-file', type=Path, help='Optional existing 0600 master-key file for headless tests; normally fetched from the gateway')
    parser.add_argument('--mib', type=int, default=1024, help='Incompressible fixture size (default: 1024 MiB)')
    parser.add_argument('--write-chunk-mib', type=int, default=0,
                        help='Optional 1–16 MiB application write size; default 0 preserves the standard cp benchmark')
    parser.add_argument('--upload-concurrency', type=int, choices=range(1, 65), help='Override bounded upload parallelism (requires a compatible daemon)')
    parser.add_argument('--download-concurrency', type=int, choices=range(1, 65), help='Override bounded download parallelism')
    parser.add_argument('--random-read-count', type=int, default=0, help='Optional cold 64 KiB random probes (0–4096), each checked against the source')
    parser.add_argument('--read-existing', help='Read-only comparison: existing root-level fixture filename')
    parser.add_argument('--expected-sha256', help='Required SHA-256 for --read-existing; --mib must also match its size')
    parser.add_argument('--trace-read-ahead', action='store_true', help='Log read scheduling decisions; diagnostic runs are not timing comparisons')
    parser.add_argument('--timeout', type=int, default=600, help='Copy/flush deadline in seconds')
    parser.add_argument('--output', required=True, type=Path, help='New JSON evidence file')
    args = parser.parse_args()
    token = os.environ.get('CLOUDFS_BENCHMARK_TOKEN', '')
    if not token:
        parser.error('Set CLOUDFS_BENCHMARK_TOKEN to a token for your test filespace.')
    parsed = urllib.parse.urlparse(args.gateway)
    if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost', '::1')):
        parser.error('The gateway must use HTTPS, except for a local test server.')
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        parser.error('The gateway must be an origin without credentials, query, or fragment.')
    if not 0 <= args.random_read_count <= 4096:
        parser.error('Random read count must be between 0 and 4096.')
    if args.mib < 1 or args.timeout < 1:
        parser.error('Size and timeout must be positive.')
    if not 0 <= args.write_chunk_mib <= 16:
        parser.error('Write chunk size must be 0 (cp) or 1–16 MiB.')
    if args.read_existing:
        if args.read_existing in ('.', '..') or '/' in args.read_existing or '\\' in args.read_existing:
            parser.error('The existing fixture must be a single root-level filename.')
        if not args.expected_sha256 or not re.fullmatch(r'[0-9a-fA-F]{64}', args.expected_sha256):
            parser.error('Read-only comparisons require the expected SHA-256.')
        if args.random_read_count:
            parser.error('Random probes require a generated local source; omit them for read-only comparisons.')
    elif args.expected_sha256:
        parser.error('--expected-sha256 requires --read-existing.')
    if args.output.exists():
        parser.error('Output already exists; choose a new evidence file.')
    if not args.daemon.is_file() or not os.access(args.daemon, os.X_OK):
        parser.error('The daemon path must point to an executable cloudfsd release build.')
    if not args.output.parent.is_dir():
        parser.error('The output directory does not exist.')
    program = str(args.daemon.resolve(strict=True))
    run = Path(tempfile.mkdtemp(prefix='cfbench-', dir='/tmp')).resolve()
    mount = run / 'mount'
    control = str(run / 'control.sock')
    fixture = args.read_existing or 'cloudfs-benchmark-' + secrets.token_hex(8) + '.bin'
    source = run / 'source.bin'
    proc = None
    log = None
    # Empty explicit configuration prevents picking up the user's normal mounts,
    # tokens, or Finder socket. Environment overrides are scrubbed below as well.
    (run / 'isolated.env').write_text('# Isolated benchmark configuration\n')
    fd = os.open(run / 'token', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as file:
        file.write(token)

    def rpc(method, params):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(args.timeout + 10)
            client.connect(control)
            client.sendall((json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}) + '\n').encode())
            with client.makefile('rb') as response:
                value = json.loads(response.readline(16 << 20))
        if 'error' in value:
            raise RuntimeError(f'{method}: {value["error"].get("message", "failed")}')
        return value['result']

    def start(cache_name):
        nonlocal proc, log
        env = {k: v for k, v in os.environ.items() if not k.startswith('CLOUDFS_')}
        env['CLOUDFS_SPILL_DIR'] = str(run)
        # Low-overhead counters prove the cold read crossed the actual object
        # transport, rather than relying only on a new daemon/cache directory.
        env['CLOUDFS_PROFILE_WRITES'] = '1'
        env['CLOUDFS_PROFILE_READS'] = '1'
        if args.trace_read_ahead:
            env['CLOUDFS_LOG_READS'] = '1'
            env['CLOUDFS_LOG_READ_AHEAD'] = '1'
        log = (run / f'{cache_name}.log').open('w')
        arguments = [program, '--env-file', str(run / 'isolated.env'),
            '--control-socket', control, '--cache-dir', str(run / cache_name),
            '--gateway', args.gateway.rstrip('/'), '--token-file', str(run / 'token')]
        if args.key_file:
            arguments += ['--key-file', str(args.key_file.resolve(strict=True))]
        if args.upload_concurrency:
            arguments += ['--upload-concurrency', str(args.upload_concurrency)]
        if args.download_concurrency:
            arguments += ['--download-concurrency', str(args.download_concurrency)]
        proc = subprocess.Popen(arguments, env=env, stdout=log, stderr=log)
        deadline = time.monotonic() + 30
        while not os.path.exists(control):
            if proc.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(f'Background service did not start; see {run}.')
            time.sleep(0.05)
        rpc('mount', {'filespace': args.filespace, 'at': str(mount), 'name': 'CloudFS benchmark'})

    def stop():
        nonlocal proc, log
        if proc is None:
            return
        try:
            if proc.poll() is None:
                rpc('unmount', {'filespace': args.filespace, 'force': False})
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=args.timeout)
            proc = None
            if log:
                log.close()
                log = None

    def digest(path):
        checksum = hashlib.sha256()
        with path.open('rb', buffering=0) as stream:
            while chunk := stream.read(4 << 20):
                checksum.update(chunk)
        return checksum.hexdigest()

    def transfer_profile(cache_name):
        records = [json.loads(line.split(' ', 1)[1])
                   for line in (run / f'{cache_name}.log').read_text().splitlines()
                   if line.startswith('CLOUDFS_WRITE_PROFILE ')]
        if not records:
            raise RuntimeError('Daemon did not provide transfer counters; use a current release build.')
        return records[-1]

    def read_profiles(cache_name):
        profiles = []
        for line in (run / f'{cache_name}.log').read_text().splitlines():
            if 'READ_PROFILE ' not in line:
                continue
            values = dict(re.findall(r'(count|bytes|peakConcurrent)=([0-9]+)', line))
            if values:
                profiles.append({key: int(value) for key, value in values.items()})
        return profiles

    def write_profiles(cache_name):
        profiles = []
        for line in (run / f'{cache_name}.log').read_text().splitlines():
            if 'WRITE_PROFILE count=' not in line:
                continue
            profile = {key: int(value) for key, value in re.findall(
                r'(count|bytes|queuedBeforeACK|maxQueuedBytes)=([0-9]+)', line)}
            batch = re.search(r'batches=\[([^]]*)\]', line)
            profile['batchesByRequestCount'] = dict((key, int(value)) for key, value in
                re.findall(r'([0-9]+):\s*([0-9]+)', batch.group(1) if batch else ''))
            profiles.append(profile)
        return profiles

    def write_fixture():
        if args.write_chunk_mib == 0:
            subprocess.run(['/bin/cp', str(source), str(mount / fixture)], check=True, timeout=args.timeout)
            return
        # A typical larger application write can let the kernel pipeline SMB
        # requests. This is a separate workload, never a substitute for the cp
        # baseline. The same remote barrier and fresh-cache checksum follow it.
        def timeout(_signal, _frame):
            raise TimeoutError(f'Application write exceeded {args.timeout} seconds.')
        previous_handler = signal.signal(signal.SIGALRM, timeout)
        signal.alarm(args.timeout)
        try:
            with source.open('rb', buffering=0) as incoming, (mount / fixture).open('xb', buffering=0) as outgoing:
                while chunk := incoming.read(args.write_chunk_mib << 20):
                    pending = memoryview(chunk)
                    while pending:
                        written = outgoing.write(pending)
                        if not written:
                            raise RuntimeError('Application write made no progress.')
                        pending = pending[written:]
                os.fsync(outgoing.fileno())
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous_handler)

    def timed_read(label):
        before = time.monotonic()
        def timeout(_signal, _frame):
            raise TimeoutError(f'{label} exceeded {args.timeout} seconds.')
        previous_handler = signal.signal(signal.SIGALRM, timeout)
        signal.alarm(args.timeout)
        try:
            actual = digest(mount / fixture)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous_handler)
        elapsed = time.monotonic() - before
        if actual != expected:
            raise RuntimeError(f'{label} SHA-256 differs; evidence and local data retained at {run}.')
        return {'seconds': elapsed, 'MiBPerSecond': args.mib / elapsed,
                'gigabitsPerSecond': args.mib * (1 << 20) * 8 / elapsed / 1e9, 'sha256Matched': True}

    try:
        copy_seconds = durable_seconds = barrier = write_profile = None
        write_smb_profiles = []
        if args.read_existing:
            print(f'Re-reading {args.mib} MiB fixture; local evidence: {run}', flush=True)
            expected = args.expected_sha256.lower()
        else:
            print(f'Generating {args.mib} MiB of incompressible test data in {run}', flush=True)
            with source.open('xb') as file:
                for _ in range(args.mib):
                    file.write(os.urandom(1 << 20))
            expected = digest(source)
            start('write-cache')
            before = time.monotonic()
            write_fixture()
            copy_seconds = time.monotonic() - before
            barrier = rpc('flush', {'filespace': args.filespace, 'path': '/', 'wait': True, 'timeoutMs': args.timeout * 1000})
            durable_seconds = time.monotonic() - before
            write_profile = transfer_profile('write-cache')
            if digest(mount / fixture) != expected:
                raise RuntimeError('Write/readback SHA-256 differs.')
            stop()
            write_smb_profiles = write_profiles('write-cache')
        start('fresh-cold-cache')
        if args.read_existing and (mount / fixture).stat().st_size != args.mib * (1 << 20):
            raise RuntimeError('Existing fixture size differs; refusing to report incorrect throughput.')
        cache_before = rpc('cache.info', {'filespace': args.filespace})
        if cache_before['usedBytes'] != 0:
            raise RuntimeError('The cold-read cache was not empty before timing.')
        rpc('flush', {'filespace': args.filespace, 'path': '/', 'wait': True, 'timeoutMs': args.timeout * 1000})
        downloads_before = transfer_profile('fresh-cold-cache')
        cold = timed_read('Cold read')
        cache_after = rpc('cache.info', {'filespace': args.filespace})
        rpc('flush', {'filespace': args.filespace, 'path': '/', 'wait': True, 'timeoutMs': args.timeout * 1000})
        downloads_after = transfer_profile('fresh-cold-cache')
        downloaded_bytes = (downloads_after.get('byteTotals', {}).get('download.receivedCiphertext', 0)
                            - downloads_before.get('byteTotals', {}).get('download.receivedCiphertext', 0))
        get_count = (downloads_after.get('counts', {}).get('download.get', 0)
                     - downloads_before.get('counts', {}).get('download.get', 0))
        if get_count == 0 or downloaded_bytes < args.mib * (1 << 20):
            raise RuntimeError('Cold read did not prove a complete remote download; do not label this throughput as cold.')
        cold['proof'] = {'cacheBytesBefore': cache_before['usedBytes'], 'cacheBytesAfter': cache_after['usedBytes'],
                         'objectGETs': get_count, 'downloadedCiphertextBytes': downloaded_bytes}
        # Capture before the warm read so transport/authorization timings describe
        # the actual cold workload. The profiler contains no object URLs or tokens.
        cold['transferProfile'] = downloads_after
        cold['latencyWindowActivations'] = [
            {'maximumBytes': int(size), 'readDeliveryMilliseconds': int(nanos) / 1_000_000}
            for size, nanos in re.findall(
                r'CLOUDFS_READ_AHEAD_WINDOW maximumBytes=(\d+) elapsedNanoseconds=(\d+)',
                (run / 'fresh-cold-cache.log').read_text())]
        warm = timed_read('Warm read')
        stop()
        cold['smbReadCountersIncludingWarmRead'] = read_profiles('fresh-cold-cache')
        random_reads = None
        if args.random_read_count:
            start('fresh-random-cache')
            random_cache_before = rpc('cache.info', {'filespace': args.filespace})
            if random_cache_before['usedBytes'] != 0:
                raise RuntimeError('Random-read cache was not empty.')
            positions = random.Random(20261009).sample(range(args.mib), min(args.random_read_count, args.mib))
            latencies = []
            def random_timeout(_signal, _frame):
                raise TimeoutError(f'Random reads exceeded {args.timeout} seconds.')
            prior_handler = signal.signal(signal.SIGALRM, random_timeout)
            signal.alarm(args.timeout)
            try:
                with source.open('rb', buffering=0) as original, (mount / fixture).open('rb', buffering=0) as remote:
                    for block in positions:
                        offset = block * (1 << 20)
                        wanted = os.pread(original.fileno(), 64 << 10, offset)
                        began = time.monotonic()
                        received = os.pread(remote.fileno(), 64 << 10, offset)
                        latencies.append(time.monotonic() - began)
                        if received != wanted:
                            raise RuntimeError('Random read differs from source.')
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, prior_handler)
            rpc('flush', {'filespace': args.filespace, 'path': '/', 'wait': True, 'timeoutMs': args.timeout * 1000})
            stop()
            random_profile = transfer_profile('fresh-random-cache')
            latencies.sort()
            random_reads = {'probeCount': len(positions), 'probeBytes': 64 << 10,
                'cacheBytesBefore': random_cache_before['usedBytes'], 'allBytesMatched': True,
                'p50Milliseconds': latencies[len(latencies)//2] * 1000,
                'p95Milliseconds': latencies[int((len(latencies)-1)*.95)] * 1000,
                'totalReadSeconds': sum(latencies),
                'objectGETs': random_profile.get('counts', {}).get('download.get', 0),
                'downloadedCiphertextBytes': random_profile.get('byteTotals', {}).get('download.receivedCiphertext', 0),
                'transferProfile': random_profile,
                'note': 'Random 64 KiB probes use distinct 1 MiB blocks; macOS may issue its own read-ahead.'}
        result = {'result': 'PASS', 'readOnlyComparison': bool(args.read_existing), 'diagnosticTracingEnabled': args.trace_read_ahead, 'gateway': args.gateway, 'filespace': args.filespace,
            'remoteFixture': fixture, 'bytes': args.mib * (1 << 20), 'sha256': expected,
            'copySeconds': copy_seconds, 'remoteDurableSeconds': durable_seconds,
            'remoteDurableMiBPerSecond': args.mib / durable_seconds if durable_seconds is not None else None,
            'remoteDurableGigabitsPerSecond': args.mib * (1 << 20) * 8 / durable_seconds / 1e9 if durable_seconds is not None else None,
            'randomReads': random_reads, 'flush': barrier, 'coldRead': cold, 'warmRead': warm, 'writeProfile': write_profile,
            'writeProducer': None if args.read_existing else ('cp' if args.write_chunk_mib == 0 else f'{args.write_chunk_mib} MiB application writes'),
            'uploadConcurrencyOverride': args.upload_concurrency,
            'downloadConcurrencyOverride': args.download_concurrency,
            'writeSMBProfiles': write_smb_profiles,
            'transport': 'macOS kernel SMB → encrypted blocks → configured object storage',
            'note': 'Cold read verifies an initially empty daemon cache and the full ciphertext downloaded through actual object GETs. Warm read may also use macOS caching. No stack sampler runs during this benchmark.'}
        with args.output.open('x') as file:
            json.dump(result, file, indent=2)
            file.write('\n')
        print(json.dumps(result, indent=2))
        print(f'Test file remains in the filespace as {fixture}. Local evidence: {run}')
    finally:
        try:
            stop()
        finally:
            # Never retain a copied bearer credential after the benchmark. Local
            # source, journal, and diagnostic logs remain for any failed recovery.
            (run / 'token').unlink(missing_ok=True)


if __name__ == '__main__':
    main()
