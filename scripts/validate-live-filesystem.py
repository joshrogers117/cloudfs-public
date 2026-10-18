#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exercise an installed daemon against an existing writable HTTPS filespace.

Uses CLOUDFS_BENCHMARK_TOKEN, creates one uniquely named remote directory,
removes only that directory after success, and retains failure evidence.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import subprocess
import tempfile
import time
import traceback
import urllib.parse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gateway', required=True)
    parser.add_argument('--filespace', required=True)
    parser.add_argument('--daemon', type=Path, required=True)
    parser.add_argument('--key-file', type=Path)
    parser.add_argument('--key-org', help='Authenticated organization ID for an explicit local key file')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--smb-log', action='store_true', help='Record SMB commands/statuses in the private evidence directory')
    parser.add_argument('--existing-file', type=Path, help='Read-only relative file to verify on cold and warm mounts')
    parser.add_argument('--existing-sha256', help='Expected SHA-256 for --existing-file')
    args = parser.parse_args()
    if args.key_file and not args.key_org:
        parser.error('--key-org is required when --key-file is supplied')
    if bool(args.existing_file) != bool(args.existing_sha256):
        parser.error('--existing-file and --existing-sha256 must be supplied together')
    if args.existing_file and (args.existing_file.is_absolute() or '..' in args.existing_file.parts
            or len(args.existing_sha256) != 64 or any(c not in '0123456789abcdef' for c in args.existing_sha256)):
        parser.error('Use a relative existing file and a lowercase SHA-256 digest')
    token = os.environ.get('CLOUDFS_BENCHMARK_TOKEN', '')
    url = urllib.parse.urlsplit(args.gateway)
    if not token or any(c in token for c in '\r\n"\\'):
        parser.error('A valid CLOUDFS_BENCHMARK_TOKEN is required.')
    if url.scheme != 'https' or url.username or url.password or url.query or url.fragment or url.path not in ('', '/'):
        parser.error('Use an HTTPS origin without credentials.')
    if args.output.exists():
        parser.error('Evidence output already exists.')
    run = Path(tempfile.mkdtemp(prefix='cflive-', dir='/tmp')).resolve()
    mount = run / 'mount'
    control = str(run / 'control.sock')
    fixture = 'cloudfs-validation-' + secrets.token_hex(8)
    root = mount / fixture
    report = {'result': 'RUNNING', 'gateway': args.gateway, 'filespace': args.filespace,
              'fixture': fixture, 'localEvidence': str(run), 'checks': {}}
    (run / 'isolated.env').write_text('# Isolated live validation\n')
    fd = os.open(run / 'token', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as file:
        file.write(token)
    proc = log = None
    phase = ''
    space = '/v1/filespaces/' + urllib.parse.quote(args.filespace, safe='')

    def rpc(method, params=None, timeout_seconds=130):
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(timeout_seconds)
            sock.connect(control)
            sock.sendall((json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method,
                                     'params': params or {'filespace': args.filespace}}) + '\n').encode())
            with sock.makefile('rb') as stream:
                value = json.loads(stream.readline(16 << 20))
        if 'error' in value:
            raise RuntimeError(f'{method}: {value["error"]}')
        return value['result']

    def api(path, method='GET', body=None):
        command = ['curl', '-sS', '--max-time', '40', '--config', '-', '--request', method,
                   '--write-out', '\n%{http_code}', args.gateway.rstrip('/') + space + path]
        if body is not None:
            command += ['--header', 'Content-Type: application/json', '--data-raw', json.dumps(body)]
        response = subprocess.run(command, input=f'header = "Authorization: Bearer {token}"\n',
                                  capture_output=True, text=True, check=True)
        data, status = response.stdout.rsplit('\n', 1)
        if not 200 <= int(status) < 300:
            raise RuntimeError(f'API {method} {path}: HTTP {status}')
        return json.loads(data) if data else None

    def start(name, cache, extra=()):
        nonlocal proc, log, phase
        phase = name
        env = {k: v for k, v in os.environ.items() if not k.startswith('CLOUDFS_')}
        env.update(CLOUDFS_SPILL_DIR=str(run), CLOUDFS_PROFILE_WRITES='1', CLOUDFS_PROFILE_READS='1')
        if args.smb_log:
            env['CLOUDFS_LOG_SMB'] = '1'
        command = [str(args.daemon.resolve()), '--env-file', str(run / 'isolated.env'),
                   '--control-socket', control, '--cache-dir', str(run / cache),
                   '--gateway', args.gateway, '--token-file', str(run / 'token')]
        command.extend(extra)
        if args.key_file:
            command += ['--key-file', str(args.key_file.resolve()),
                        '--key-filespace', args.filespace,
                        '--key-gateway', args.gateway,
                        '--key-org', args.key_org]
        log = (run / (name + '.log')).open('w')
        proc = subprocess.Popen(command, env=env, stdout=log, stderr=log)
        deadline = time.monotonic() + 30
        while not Path(control).exists():
            if proc.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('Daemon did not start; inspect local evidence.')
            time.sleep(.05)
        rpc('mount', {'filespace': args.filespace, 'at': str(mount), 'name': 'CloudFS live validation'})

    def stop():
        nonlocal proc, log
        if proc is not None:
            try:
                if proc.poll() is None:
                    # macOS can briefly retain a vnode after the last read/close.
                    # Exercise graceful unmount again; never force away open I/O
                    # or retry an unrelated daemon error.
                    for attempt in range(3):
                        try:
                            rpc('unmount', {'filespace': args.filespace, 'force': False})
                            break
                        except RuntimeError as error:
                            if 'The filespace is still mounted.' not in str(error) or attempt == 2:
                                raise
                            time.sleep(.3)
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    proc.wait(timeout=130)
                proc = None
                log.close()
                log = None

    def flush():
        return rpc('flush', {'filespace': args.filespace, 'path': '/', 'wait': True, 'timeoutMs': 120000})

    def profile():
        rows = [json.loads(line.split(' ', 1)[1]) for line in (run / (phase + '.log')).read_text().splitlines()
                if line.startswith('CLOUDFS_WRITE_PROFILE ')]
        return rows[-1] if rows else {'counts': {}, 'byteTotals': {}}

    def listing(parent):
        rows = api('/items?' + urllib.parse.urlencode({'parent': parent}))
        return rows['items']

    def checked(name, value=True):
        report['checks'][name] = value
        print(name + ': PASS', flush=True)

    def verify_payload(actual, expected, label):
        if actual == expected:
            return
        differences = [i for i, (a, b) in enumerate(zip(actual, expected)) if a != b]
        detail = {'phase': phase, 'label': label,
                  'expectedBytes': len(expected), 'actualBytes': len(actual),
                  'expectedSHA256': hashlib.sha256(expected).hexdigest(),
                  'actualSHA256': hashlib.sha256(actual).hexdigest(),
                  'differentBytes': len(differences) + abs(len(actual) - len(expected)),
                  'firstDifferingOffsets': differences[:16],
                  'actualZeroBytes': actual.count(0), 'expectedZeroBytes': expected.count(0)}
        # These are this test's synthetic payloads, never an existing user file.
        # Preserve both privately so an assertion cannot discard the only
        # evidence of a short read, displaced range, or silent changed bytes.
        for name, data in [('expected-payload.bin', expected), ('actual-payload.bin', actual)]:
            fd = os.open(run / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'wb') as file:
                file.write(data)
        report['payloadMismatch'] = detail
        raise AssertionError('Payload mismatch: ' + json.dumps(detail, sort_keys=True))

    def set_xattr(path, name, value):
        subprocess.run(['/usr/bin/xattr', '-wx', name, value.hex(), str(path)], check=True, timeout=30)

    def get_xattr(path, name):
        return bytes.fromhex(subprocess.check_output(['/usr/bin/xattr', '-px', name, str(path)], text=True, timeout=30))

    def wait_for(condition, seconds=15):
        deadline = time.monotonic() + seconds
        while not condition():
            if time.monotonic() > deadline:
                raise RuntimeError('Timed out waiting for remote change/cache admission')
            time.sleep(.1)

    def timeout(_signal, _frame):
        raise TimeoutError('Live filesystem validation exceeded its 12-minute deadline')

    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(720)
    try:
        start('write', 'write-cache')
        # GUI/Finder clients can vanish before a reply. Neither SIGPIPE nor an
        # accepted peer's setup failure may kill the engine or its listener.
        for _ in range(40):
            with socket.socket(socket.AF_UNIX) as abandoned:
                abandoned.settimeout(10)
                abandoned.connect(control)
                abandoned.sendall(b'{"jsonrpc":"2.0","id":1,"method":"system.version","params":{}}\n')
            time.sleep(.02)
        rpc('system.version', timeout_seconds=10)
        assert proc.poll() is None, 'Engine exited after a control client disconnected'
        checked('closedControlClients', 40)
        root.mkdir()
        path = root / 'Résumé-雪.bin'
        payload = bytearray(os.urandom((9 << 20) + 137))
        with path.open('xb', buffering=0) as f:
            f.write(payload)
            os.fsync(f.fileno())
        flush()
        with path.open('r+b', buffering=0) as f:
            patch = os.urandom(4096)
            offset = (1 << 20) - 19
            os.pwrite(f.fileno(), patch, offset)
            payload[offset:offset + len(patch)] = patch
            f.truncate((8 << 20) + 17)
            del payload[(8 << 20) + 17:]
            f.truncate((12 << 20) + 33)
            payload.extend(bytes((12 << 20) + 33 - len(payload)))
            os.fsync(f.fileno())
        flush()
        verify_payload(path.read_bytes(), payload, 'partial-write-truncate-zero-fill')
        checked('partialWriteTruncateAndZeroFill')
        renamed = root / 'Renamed-雪.bin'
        path.rename(renamed)
        path = renamed
        assert not (root / 'Résumé-雪.bin').exists()
        set_xattr(path, 'com.cloudfs.validation', b'live-release-0.1.7')
        set_xattr(path, 'com.apple.ResourceFork', b'CloudFS resource fork\x00\xff')
        os.utime(path, (1577934245, 1577934245))
        subprocess.run(['/usr/bin/chflags', 'hidden', str(path)], check=True, timeout=20)
        temporary = root / 'replacement.tmp'
        target = root / 'atomic-save.txt'
        target.write_bytes(b'old')
        temporary.write_bytes(b'new atomic content')
        # Replace while both acknowledged writes may still be uploading. The
        # namespace adapter must order the destination delete and source rename.
        os.replace(temporary, target)
        sequence = root / 'frames'
        sequence.mkdir()
        frames = [os.urandom(64 << 10) for _ in range(8)]
        for i, data in enumerate(frames):
            (sequence / f'frame{i:04d}.bin').write_bytes(data)
        flush()
        directory = next(item for item in listing('root') if item['name'] == fixture)
        item = next(item for item in listing(directory['id']) if item['name'] == path.name)
        extent = api('/blocks/' + urllib.parse.quote(item['id'], safe='') + '/range?' +
                     urllib.parse.urlencode({'offset': len(payload) - 16, 'length': 16}))
        assert extent['format'] == 2 and extent['firstBlockIndex'] == 12 and len(extent['blocks']) == 1
        checked('demandManifestTailSeek', {'firstBlockIndex': extent['firstBlockIndex'], 'returnedBlocks': len(extent['blocks'])})
        status = rpc('status')
        assert status['storage']['requests'] > 0 and status['storage']['requestDurationMs'] is not None
        assert status['gatewayLatencyMs'] is not None
        checked('separateStorageAndGatewayTelemetry', status)
        stop()

        start('cold', 'read-cache')
        assert rpc('cache.info')['usedBytes'] == 0
        if args.existing_file:
            digest = hashlib.sha256((mount / args.existing_file).read_bytes()).hexdigest()
            assert digest == args.existing_sha256, 'Existing file cold read differs'
            checked('existingFileColdRead', {'path': str(args.existing_file), 'sha256': digest})
        verify_payload(path.read_bytes(), payload, 'cold-remount')
        assert target.read_bytes() == b'new atomic content'
        assert get_xattr(path, 'com.cloudfs.validation') == b'live-release-0.1.7'
        assert get_xattr(path, 'com.apple.ResourceFork') == b'CloudFS resource fork\x00\xff'
        stat = path.stat()
        assert abs(stat.st_mtime - 1577934245) < 1, f'mtime differs: {stat.st_mtime}'
        assert stat.st_flags & 0x8000, 'Hidden flag did not persist'
        assert not any(p.name.startswith('._') for p in root.iterdir()), 'AppleDouble sidecar appeared'
        flush()
        cold = profile()
        assert cold['counts'].get('download.get', 0) > 0
        checked('coldReadAndMetadataAcrossRemount', {'sha256': hashlib.sha256(payload).hexdigest(),
                'objectGETs': cold['counts']['download.get'], 'mtime': stat.st_mtime,
                'hidden': True, 'extendedAttribute': True, 'resourceFork': True, 'atomicReplace': True})
        stop()

        start('warm-remount', 'read-cache')
        assert rpc('cache.info')['usedBytes'] > 0
        if args.existing_file:
            digest = hashlib.sha256((mount / args.existing_file).read_bytes()).hexdigest()
            assert digest == args.existing_sha256, 'Existing file warm read differs'
            checked('existingFileWarmRead', {'path': str(args.existing_file), 'sha256': digest})
        verify_payload(path.read_bytes(), payload, 'warm-remount')
        assert target.read_bytes() == b'new atomic content'
        flush()
        warm = profile()
        assert warm['counts'].get('download.get', 0) == 0, 'Persisted-cache read performed object GETs'
        checked('persistedCacheAfterDaemonRestart', {'objectGETs': 0, 'bytesVerified': len(payload) + len(b'new atomic content')})
        # Watching the directory (as Finder does) requests SMB CHANGE_NOTIFY.
        # Repeated stat() alone can remain in the kernel's negative-name cache.
        watched = os.open(root, os.O_RDONLY)
        queue = select.kqueue()
        try:
            event = select.kevent(watched, filter=select.KQ_FILTER_VNODE,
                                 flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                                 fflags=select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND | select.KQ_NOTE_ATTRIB)
            queue.control([event], 0, 0)
            external = api('/items', 'POST', {'parent': directory['id'], 'name': 'external-change.txt', 'isDir': False, 'size': 0})
            began = time.monotonic()
            assert queue.control(None, 1, 15), 'No kernel directory notification for external create'
            seen = time.monotonic() - began
            wait_for(lambda: 'external-change.txt' in os.listdir(root))
            assert (root / 'external-change.txt').exists()
            api('/items/' + urllib.parse.quote(external['id'], safe=''), 'DELETE')
            assert queue.control(None, 1, 15), 'No kernel directory notification for external delete'
            wait_for(lambda: 'external-change.txt' not in os.listdir(root))
            checked('externalCreateAndDeleteVisibleThroughMount', {'kernelNotificationSeconds': seen})
        finally:
            queue.close()
            os.close(watched)
        stop()

        start('directory-prefetch', 'prefetch-cache')
        assert rpc('cache.info')['usedBytes'] == 0
        assert len(list(sequence.iterdir())) == 8
        for i in range(3):
            assert (sequence / f'frame{i:04d}.bin').read_bytes() == frames[i]
        wait_for(lambda: rpc('cache.info')['usedBytes'] >= 5 * (64 << 10))
        flush()
        count = profile()['counts'].get('download.get', 0)
        assert count == 5, f'Expected three demand + two speculative GETs, got {count}'
        checked('directoryAwarePrefetch', {'filesOpened': 3, 'objectGETs': count, 'residentBytes': rpc('cache.info')['usedBytes']})
        stop()

        start('pending-budget', 'budget-cache', ['--pending-write-limit', '0'])
        # A zero pending-write allowance must reject new writes with ENOSPC,
        # while demand downloads continue to use their separate cache budget.
        assert rpc('cache.info')['pendingWriteLimitBytes'] == 0
        with path.open('rb', buffering=0) as f:
            assert f.read(64 << 10) == payload[:64 << 10]
        budget_file = root / 'budget-rejection.bin'
        errors = []
        fd = os.open(budget_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_SYNC, 0o600)
        try:
            try:
                os.write(fd, os.urandom(64 << 10))
                os.fsync(fd)
            except OSError as error:
                errors.append({'operation': 'write/fsync', 'errno': error.errno})
        finally:
            try:
                os.close(fd)
            except OSError as error:
                errors.append({'operation': 'close', 'errno': error.errno})
        # macOS SMB may return ENXIO from a synchronous write and surface the
        # server's DISK_FULL as ENOSPC on close. Capture both system calls.
        assert any(e['errno'] == errno.ENOSPC for e in errors), f'No ENOSPC for zero pending budget: {errors}'
        assert all(e['errno'] in (errno.ENOSPC, errno.ENXIO) for e in errors), errors
        budget = rpc('cache.info')
        assert budget['pendingWriteUsedBytes'] == 0 and budget['pendingWriteReservedBytes'] == 0
        assert next(i for i in listing(directory['id']) if i['name'] == budget_file.name)['size'] == 0
        checked('pendingWriteDiskBudget', {'errors': errors, 'usedBytes': 0, 'reservedBytes': 0, 'remoteSize': 0, 'demandReadAllowed': True})
        # Bound cleanup to the one server-minted directory created by this run.
        api('/items/' + urllib.parse.quote(directory['id'], safe='') + '?recursive=true', 'DELETE')
        report['ownedFixtureRemoved'] = True
        checked('recursiveDelete')
        report['result'] = 'PASS'
    except Exception as error:
        report['result'] = 'FAIL'
        report['failure'] = str(error)
        report['failurePhase'] = phase
        report['traceback'] = traceback.format_exc()
        raise
    finally:
        signal.alarm(0)
        try:
            stop()
        finally:
            (run / 'token').unlink(missing_ok=True)
            args.output.write_text(json.dumps(report, indent=2) + '\n')
            print('Evidence: ' + str(args.output), flush=True)


if __name__ == '__main__':
    main()
