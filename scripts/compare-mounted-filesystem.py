#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compare POSIX open-file, rename, unlink, and advisory-lock behavior.

Run once per explicitly supplied mounted volume, then compare the JSON reports:
  python3 compare-mounted-filesystem.py --label lucidlink --mount /Volumes/LucidLink --report /tmp/lucidlink.json
  python3 compare-mounted-filesystem.py --label cloudfs --mount /Volumes/CloudFS --report /tmp/cloudfs.json

All mutations stay in one newly created UUID directory at the mount root. The
fixture directory is intentionally retained, including on failure. The script
uses no credentials, gateway, administrator APIs, or deployment tools.
"""
import argparse
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import time
import uuid

OP_TIMEOUT_SECONDS = 8
LOCK_TIMEOUT_SECONDS = 5
MAX_READ_BYTES = 1 << 20
SCRIPT_PATH = Path(__file__).resolve()
O_NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def close_fd(fd, label='file close'):
    with bounded(label):
        os.close(fd)


class CheckFailure(RuntimeError):
    pass


class OperationTimeout(TimeoutError):
    pass


def bounded(label, seconds=OP_TIMEOUT_SECONDS):
    """Context manager-style callable guard for potentially blocking local I/O."""
    class Guard:
        def __enter__(self):
            self.previous = signal.getsignal(signal.SIGALRM)

            def expired(_signum, _frame):
                raise OperationTimeout(f'{label} exceeded {seconds}s')

            signal.signal(signal.SIGALRM, expired)
            signal.setitimer(signal.ITIMER_REAL, seconds)
            return self

        def __exit__(self, _kind, _value, _traceback):
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, self.previous)
            return False
    return Guard()


def write_all(fd, data):
    offset = 0
    while offset < len(data):
        with bounded('file write'):
            count = os.write(fd, data[offset:])
        if count <= 0:
            raise OSError('file write made no progress')
        offset += count


def create_file(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW
    with bounded('exclusive file create'):
        fd = os.open(path, flags, 0o600)
    try:
        write_all(fd, data)
        with bounded('file fsync'):
            os.fsync(fd)
        with bounded('created fixture metadata check'):
            info = os.fstat(fd)
            path_info = os.stat(path, follow_symlinks=False)
        if info.st_size != len(data) or not stat.S_ISREG(path_info.st_mode):
            raise OSError('created fixture file failed regular-file or size check')
        return {'device': info.st_dev, 'inode': info.st_ino, 'size': info.st_size}
    finally:
        close_fd(fd)


def read_fd(fd):
    with bounded('descriptor read'):
        os.lseek(fd, 0, os.SEEK_SET)
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, MAX_READ_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_READ_BYTES:
                raise OSError('fixture unexpectedly exceeds bounded read size')
        return b''.join(chunks)


def append_fd(fd, data):
    with bounded('descriptor append'):
        os.lseek(fd, 0, os.SEEK_END)
    write_all(fd, data)
    with bounded('descriptor fsync'):
        os.fsync(fd)


def lock_probe(path):
    """Child-process mode: try the one-byte POSIX record lock without blocking."""
    try:
        fd = os.open(path, os.O_RDWR | O_NOFOLLOW)
    except OSError:
        print('ERROR')
        return 2
    try:
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 0, os.SEEK_SET)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                print('BLOCKED')
                return 0
            print('ERROR')
            return 2
        else:
            fcntl.lockf(fd, fcntl.LOCK_UN, 1, 0, os.SEEK_SET)
            print('ACQUIRED')
            return 0
    finally:
        os.close(fd)


def run_lock_probe(path, expected):
    try:
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), '--_lock-probe', str(path)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=LOCK_TIMEOUT_SECONDS, check=False,
            env={key: value for key, value in os.environ.items() if not key.startswith('CLOUDFS_')},
        )
    except subprocess.TimeoutExpired:
        raise CheckFailure('lock child did not finish within its bounded wait') from None
    observed = result.stdout.strip()
    passed = result.returncode == 0 and observed == expected
    return passed, {'expected': expected, 'observed': observed or 'no response',
                    'childExitCode': result.returncode}


def pathname_observer(path, old_hex, new_hex):
    """Child mode: sample one pathname until the parent sends STOP."""
    old_data = bytes.fromhex(old_hex)
    new_data = bytes.fromhex(new_hex)
    counts = {'observations': 0, 'old': 0, 'new': 0, 'enoent': 0, 'other': 0, 'errors': 0}
    print('READY', flush=True)
    while True:
        readable, _, _ = select.select([sys.stdin], [], [], 0.001)
        if readable:
            command = sys.stdin.readline()
            if not command or command.strip() == 'STOP':
                break
        counts['observations'] += 1
        try:
            fd = os.open(path, os.O_RDONLY | O_NOFOLLOW)
        except FileNotFoundError:
            counts['enoent'] += 1
            continue
        except OSError:
            counts['errors'] += 1
            continue
        try:
            chunks = []
            size = 0
            while size <= MAX_READ_BYTES:
                data = os.read(fd, min(65536, MAX_READ_BYTES + 1 - size))
                if not data:
                    break
                chunks.append(data)
                size += len(data)
            observed = b''.join(chunks)
            if observed == old_data:
                counts['old'] += 1
            elif observed == new_data:
                counts['new'] += 1
            else:
                counts['other'] += 1
        except OSError:
            counts['errors'] += 1
        finally:
            os.close(fd)
    print(json.dumps(counts, sort_keys=True), flush=True)
    return 0


def start_pathname_observer(path, old_data, new_data):
    process = subprocess.Popen(
        [sys.executable, str(SCRIPT_PATH), '--_path-observer', str(path),
         old_data.hex(), new_data.hex()],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, bufsize=1,
        env={key: value for key, value in os.environ.items() if not key.startswith('CLOUDFS_')},
    )
    ready, _, _ = select.select([process.stdout], [], [], LOCK_TIMEOUT_SECONDS)
    if not ready:
        terminate_child_bounded(process)
        raise CheckFailure('pathname observer did not become ready within its bounded wait')
    line = process.stdout.readline().strip()
    if line != 'READY':
        terminate_child_bounded(process)
        raise CheckFailure('pathname observer failed before readiness')
    return process


def terminate_child_bounded(process):
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        process.kill()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        raise CheckFailure('child process could not be stopped within bounded waits') from None


def stop_pathname_observer(process):
    if process.poll() is None and process.stdin:
        try:
            process.stdin.write('STOP\n')
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        try:
            process.stdin.close()
        except OSError:
            pass
    try:
        process.wait(timeout=LOCK_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        terminate_child_bounded(process)
        raise CheckFailure('pathname observer required forced termination after its stop request')
    ready, _, _ = select.select([process.stdout], [], [], LOCK_TIMEOUT_SECONDS)
    if not ready:
        raise CheckFailure('pathname observer did not return bounded counts')
    line = process.stdout.readline().strip()
    try:
        counts = json.loads(line)
    except json.JSONDecodeError:
        raise CheckFailure('pathname observer returned malformed counts') from None
    if process.returncode != 0:
        raise CheckFailure('pathname observer exited unsuccessfully')
    return counts


class VolumeComparison:
    def __init__(self, mount, label, *, require_mount=True):
        self.mount = Path(mount)
        self.label = label
        self.require_mount = require_mount
        self.run_id = uuid.uuid4().hex
        self.directory_name = f'posix-compare-{self.run_id}'
        self.fixture_dir = self.mount / self.directory_name
        self.checks = []
        self.groups = []
        self.current_group = 'fixture-setup'
        self.fixture = None
        self.observer_counts = None
        self.observer_operations = []

    def check(self, name, condition, details):
        item = {'group': self.current_group, 'name': name,
                'pass': bool(condition), 'details': details}
        self.checks.append(item)
        print(f"{name}: {'PASS' if condition else 'FAIL'}", flush=True)
        if not condition:
            raise CheckFailure(name)

    def run_group(self, name, callback):
        self.current_group = name
        try:
            callback()
        except Exception as exc:
            error = str(exc).replace('\n', ' ')[:240] or type(exc).__name__
            result = {'name': name, 'pass': False, 'error': error}
            if self.observer_counts is not None and name == 'concurrent-path-observer':
                result['observerCounts'] = self.observer_counts
                result['replacementOperations'] = self.observer_operations
        else:
            result = {'name': name, 'pass': True}
        self.groups.append(result)
        print(f"group {name}: {'PASS' if result['pass'] else 'FAIL'}", flush=True)
        self.current_group = None

    def run(self):
        with bounded('mount path validation'):
            mount_absolute = self.mount.is_absolute()
            mount_symlink = self.mount.is_symlink()
            mount_directory = self.mount.is_dir()
            mount_resolved = self.mount.resolve(strict=True) if mount_directory else self.mount
        if not mount_absolute or mount_symlink:
            raise CheckFailure('mount path must be absolute and not a symlink')
        if not mount_directory or mount_resolved != self.mount:
            raise CheckFailure('mount path must be an existing canonical directory')
        if self.mount == Path('/'):
            raise CheckFailure('refusing to use the filesystem root as a test mount')
        with bounded('mounted volume check'):
            is_mount = os.path.ismount(self.mount)
        if self.require_mount and not is_mount:
            raise CheckFailure('supplied path is not a mounted volume')

        with bounded('mount root metadata check'):
            root_info = self.mount.stat()
        try:
            with bounded('exclusive fixture-directory create'):
                os.mkdir(self.fixture_dir, 0o700)
        except OSError as exc:
            raise CheckFailure(f'could not create unique fixture directory ({exc.errno})') from None
        with bounded('fixture directory metadata check'):
            fixture_info = self.fixture_dir.stat(follow_symlinks=False)
            fixture_is_link = self.fixture_dir.is_symlink()
            fixture_is_dir = self.fixture_dir.is_dir()
            fixture_resolved = self.fixture_dir.resolve(strict=True)
        if (fixture_is_link or not fixture_is_dir
                or fixture_info.st_dev != root_info.st_dev
                or fixture_resolved.parent != self.mount):
            raise CheckFailure('fixture directory escaped or changed mount identity')

        old_data = b'old-inode-content\n'
        replacement_data = b'replacement-path-content\n'
        unlink_data = b'open-inode-survives-unlink\n'
        lock_data = b'lock\n'
        observer_old = b'A' * 4096
        observer_new = b'B' * 4096
        source_names = [f'observer-source-{index:02d}.bin' for index in range(24)]
        fixture_files = {
            'rename-target.txt': old_data,
            'rename-source.txt': replacement_data,
            'unlink-open.txt': unlink_data,
            'lock-probe.bin': lock_data,
            'observer-target.bin': observer_old,
        }
        for index, name in enumerate(source_names):
            fixture_files[name] = observer_new if index % 2 == 0 else observer_old
        identities = {}
        for name, data in fixture_files.items():
            identities[name] = create_file(self.fixture_dir / name, data)
        self.fixture = {
            'directory': self.directory_name,
            'path': str(self.fixture_dir),
            'createdFiles': sorted(fixture_files),
            'cleanup': 'none; fixture directory is retained, including on failure',
        }
        self.check('exclusive UUID fixture setup completed', len(identities) == 29,
                   {'createdFiles': len(identities), 'observerReplacements': len(source_names)})

        self.run_group('rename-overwrite-open-descriptor',
                       lambda: self.rename_group(old_data, replacement_data, identities))
        self.run_group('unlink-open-descriptor', lambda: self.unlink_group(unlink_data, identities))
        self.run_group('posix-record-lock', lambda: self.lock_group())
        self.run_group('concurrent-path-observer',
                       lambda: self.observer_group(observer_old, observer_new, source_names))

        self.fixture.update({
            'renameEffect': 'rename-source.txt may be moved over rename-target.txt if that group completed',
            'observerEffect': '24 precreated source files may be moved over observer-target.bin',
            'unlinkEffect': 'unlink-open.txt may be absent if that group completed',
        })
        passed = all(group['pass'] for group in self.groups)
        return {'result': 'PASS' if passed else 'FAIL',
                'validationClass': 'diagnostic-local-posix-comparison',
                'label': self.label, 'mount': str(self.mount),
                'groups': self.groups, 'checks': self.checks,
                'observerLimit': 'Finite concurrent sampling can find missing, mixed, or erroneous reads but cannot prove all replacements atomic.',
                'lockMethod': 'fcntl.lockf POSIX record lock, probed by independent child processes',
                'fixture': self.fixture}

    def rename_group(self, old_data, replacement_data, identities):
        replacement_path = self.fixture_dir / 'rename-target.txt'
        source_path = self.fixture_dir / 'rename-source.txt'
        old_tail = b'write-through-old-open-descriptor\n'
        fd = None
        try:
            with bounded('open old rename target'):
                fd = os.open(replacement_path, os.O_RDWR | O_NOFOLLOW)
            with bounded('old descriptor fstat before rename'):
                old_open_before = os.fstat(fd)
            with bounded('same-directory rename-overwrite'):
                os.replace(source_path, replacement_path)
            with bounded('replacement path metadata check'):
                path_info = replacement_path.stat(follow_symlinks=False)
                old_open_after = os.fstat(fd)
            old_read = read_fd(fd)
            with bounded('fresh replacement pathname read'):
                path_read = replacement_path.read_bytes()
            identity_ok = ((old_open_before.st_dev, old_open_before.st_ino)
                           == (old_open_after.st_dev, old_open_after.st_ino)
                           and (path_info.st_dev, path_info.st_ino)
                           == (identities['rename-source.txt']['device'], identities['rename-source.txt']['inode'])
                           and (path_info.st_dev, path_info.st_ino)
                           != (old_open_after.st_dev, old_open_after.st_ino))
            self.check('rename-overwrite keeps old descriptor on old inode',
                       identity_ok and old_read == old_data,
                       {'oldDescriptorBytes': len(old_read), 'oldExpectedBytes': len(old_data),
                        'oldDescriptorSHA256': sha256(old_read), 'oldExpectedSHA256': sha256(old_data),
                        'oldIdentityBefore': {'device': old_open_before.st_dev, 'inode': old_open_before.st_ino},
                        'oldIdentityAfter': {'device': old_open_after.st_dev, 'inode': old_open_after.st_ino},
                        'replacementPathIdentity': {'device': path_info.st_dev, 'inode': path_info.st_ino},
                        'replacementSourceIdentity': {
                            'device': identities['rename-source.txt']['device'],
                            'inode': identities['rename-source.txt']['inode']},
                        'freshPathBytes': len(path_read), 'freshPathSHA256': sha256(path_read),
                        'oldDescriptorIdentityStable': (old_open_before.st_dev, old_open_before.st_ino)
                            == (old_open_after.st_dev, old_open_after.st_ino),
                        'replacementIdentityMatchesSource': (path_info.st_dev, path_info.st_ino)
                            == (identities['rename-source.txt']['device'], identities['rename-source.txt']['inode'])})
            self.check('fresh pathname reads replacement bytes', path_read == replacement_data,
                       {'observedBytes': len(path_read), 'expectedBytes': len(replacement_data),
                        'observedSHA256': sha256(path_read), 'expectedSHA256': sha256(replacement_data)})
            append_fd(fd, old_tail)
            old_after_write = read_fd(fd)
            with bounded('replacement pathname read after old-handle write'):
                fresh_after_write = replacement_path.read_bytes()
            self.check('old descriptor remains writable after replacement',
                       old_after_write == old_data + old_tail and fresh_after_write == replacement_data,
                       {'oldDescriptorBytes': len(old_after_write), 'oldDescriptorSHA256': sha256(old_after_write),
                        'replacementPathBytes': len(fresh_after_write),
                        'replacementPathSHA256': sha256(fresh_after_write)})
        finally:
            if fd is not None:
                close_fd(fd)

    def unlink_group(self, unlink_data, identities):
        unlink_path = self.fixture_dir / 'unlink-open.txt'
        unlink_tail = b'continued-write-after-unlink\n'
        unlink_fd = None
        try:
            with bounded('open unlink target'):
                unlink_fd = os.open(unlink_path, os.O_RDWR | O_NOFOLLOW)
            with bounded('unlinked target fstat before unlink'):
                open_identity = os.fstat(unlink_fd)
            with bounded('unlink open fixture'):
                os.unlink(unlink_path)
            missing = False
            try:
                with bounded('fresh pathname lookup after unlink'):
                    os.stat(unlink_path, follow_symlinks=False)
            except FileNotFoundError:
                missing = True
            self.check('unlinked pathname is absent', missing, {})
            with bounded('unlinked descriptor fstat'):
                still_open = os.fstat(unlink_fd)
            held_data = read_fd(unlink_fd)
            identity_ok = ((open_identity.st_dev, open_identity.st_ino)
                           == (still_open.st_dev, still_open.st_ino)
                           == (identities['unlink-open.txt']['device'], identities['unlink-open.txt']['inode']))
            self.check('open descriptor retains readable unlinked inode',
                       identity_ok and held_data == unlink_data,
                       {'descriptorBytes': len(held_data), 'expectedBytes': len(unlink_data),
                        'descriptorSHA256': sha256(held_data), 'expectedSHA256': sha256(unlink_data),
                        'descriptorIdentityStable': identity_ok})
            append_fd(unlink_fd, unlink_tail)
            held_after_write = read_fd(unlink_fd)
            with bounded('unlinked descriptor fstat after write'):
                after_write_stat = os.fstat(unlink_fd)
            self.check('open descriptor remains writable after unlink',
                       held_after_write == unlink_data + unlink_tail
                           and after_write_stat.st_size == len(unlink_data + unlink_tail),
                       {'descriptorBytes': len(held_after_write), 'descriptorSHA256': sha256(held_after_write),
                        'fstatSize': after_write_stat.st_size})
        finally:
            if unlink_fd is not None:
                close_fd(unlink_fd)

    def lock_group(self):
        lock_path = self.fixture_dir / 'lock-probe.bin'
        with bounded('open lock fixture'):
            lock_fd = os.open(lock_path, os.O_RDWR | O_NOFOLLOW)
        try:
            with bounded('acquire parent POSIX record lock'):
                fcntl.lockf(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 0, os.SEEK_SET)
            conflict_ok, conflict = run_lock_probe(lock_path, 'BLOCKED')
            self.check('child process cannot take held POSIX record lock', conflict_ok, conflict)
            with bounded('release parent POSIX record lock'):
                fcntl.lockf(lock_fd, fcntl.LOCK_UN, 1, 0, os.SEEK_SET)
            release_ok, released = run_lock_probe(lock_path, 'ACQUIRED')
            self.check('child process acquires POSIX record lock after release', release_ok, released)
        finally:
            try:
                with bounded('final POSIX record unlock'):
                    fcntl.lockf(lock_fd, fcntl.LOCK_UN, 1, 0, os.SEEK_SET)
            except OSError:
                pass
            close_fd(lock_fd)

    def observer_group(self, old_data, new_data, source_names):
        target = self.fixture_dir / 'observer-target.bin'
        process = None
        replacement_error = None
        counts = None
        try:
            process = start_pathname_observer(target, old_data, new_data)
            for name in source_names:
                started = time.monotonic()
                try:
                    with bounded('same-directory observed replacement'):
                        os.replace(self.fixture_dir / name, target)
                except Exception:
                    self.observer_operations.append({'source': name,
                        'elapsedMs': round((time.monotonic() - started) * 1000), 'completed': False})
                    raise
                self.observer_operations.append({'source': name,
                    'elapsedMs': round((time.monotonic() - started) * 1000), 'completed': True})
                time.sleep(0.002)
        except Exception as exc:
            replacement_error = str(exc).replace('\n', ' ')[:200] or type(exc).__name__
        finally:
            if process is not None:
                try:
                    counts = stop_pathname_observer(process)
                    self.observer_counts = counts
                except Exception as exc:
                    if replacement_error is None:
                        replacement_error = str(exc).replace('\n', ' ')[:200] or type(exc).__name__
        if replacement_error is not None:
            raise CheckFailure(f'observer sequence failed: {replacement_error}')
        total = sum(counts[key] for key in ('old', 'new', 'enoent', 'other', 'errors'))
        self.check('observer sampled while 24 replacements were issued', counts['observations'] == total
                   and total > 0 and len(source_names) == 24,
                   {'iterations': len(source_names), 'observerReadyBeforeFirstRename': True,
                    'observations': total, 'counts': counts,
                    'replacementOperations': self.observer_operations})
        self.check('concurrent pathname samples were only complete old or new payloads',
                   counts['enoent'] == 0 and counts['other'] == 0 and counts['errors'] == 0,
                   {'old': counts['old'], 'new': counts['new'], 'enoent': counts['enoent'],
                    'other': counts['other'], 'errors': counts['errors'],
                    'finiteSamplingLimit': 'Passing finite sampling does not prove every replacement was atomic.'})


def validate_cli_paths(mount_arg, report_arg):
    mount = Path(mount_arg)
    if not mount.is_absolute() or mount.is_symlink() or not mount.is_dir():
        raise CheckFailure('--mount must be an existing absolute directory without symlink redirection')
    if mount.resolve(strict=True) != mount or mount == Path('/') or not os.path.ismount(mount):
        raise CheckFailure('--mount must be a canonical mounted volume and cannot be /')
    report = Path(report_arg)
    if not report.is_absolute():
        raise CheckFailure('--report must be an absolute path')
    parent = report.parent
    if parent.is_symlink() or not parent.is_dir() or parent.resolve(strict=True) != parent:
        raise CheckFailure('--report parent must be an existing canonical directory')
    report = parent / report.name
    try:
        report.relative_to(mount)
    except ValueError:
        pass
    else:
        raise CheckFailure('--report must be outside the supplied mounted volume')
    if report.exists() or report.is_symlink():
        raise CheckFailure('--report already exists; refusing to overwrite')
    return mount, report


def write_report(path, value):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        data = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
        write_all(fd, data)
        with bounded('report fsync'):
            os.fsync(fd)
    finally:
        os.close(fd)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) == 2 and argv[0] == '--_lock-probe':
        return lock_probe(argv[1])
    if len(argv) == 4 and argv[0] == '--_path-observer':
        return pathname_observer(argv[1], argv[2], argv[3])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True, help='comparison label, for example lucidlink or cloudfs')
    parser.add_argument('--mount', required=True, help='absolute path to the mounted volume to probe')
    parser.add_argument('--report', required=True, help='new absolute JSON report path outside the mounted volume')
    args = parser.parse_args(argv)

    started = time.monotonic()
    report_path = None
    runner = None
    try:
        with bounded('mount and report preflight', 10):
            mount, report_path = validate_cli_paths(args.mount, args.report)
        runner = VolumeComparison(mount, args.label)
        value = runner.run()
        value['elapsedMs'] = round((time.monotonic() - started) * 1000)
        write_report(report_path, value)
        print(json.dumps({'result': value['result'], 'validationClass': value['validationClass'],
                          'report': str(report_path),
                          'fixture': value['fixture']['path']}, sort_keys=True))
        return 0 if value['result'] == 'PASS' else 1
    except Exception as exc:
        message = str(exc).replace('\n', ' ')[:300] or type(exc).__name__
        value = {'result': 'FAIL', 'validationClass': 'diagnostic-local-posix-comparison',
                 'label': args.label, 'mount': args.mount,
                 'elapsedMs': round((time.monotonic() - started) * 1000),
                 'error': message,
                 'checks': runner.checks if runner else [],
                 'groups': runner.groups if runner else [],
                 'observerCounts': runner.observer_counts if runner else None,
                 'fixture': runner.fixture if runner else None}
        fixture_exists = False
        if runner:
            try:
                with bounded('failure fixture metadata check', 3):
                    fixture_exists = runner.fixture_dir.exists()
            except OSError:
                fixture_exists = False
        if runner and fixture_exists:
            value['fixture'] = {'directory': runner.directory_name,
                                'path': str(runner.fixture_dir),
                                'cleanup': 'none; fixture directory retained'}
        report_written = False
        if report_path is not None:
            try:
                write_report(report_path, value)
                report_written = True
            except OSError:
                pass
        print(json.dumps({'result': 'FAIL', 'validationClass': 'diagnostic-local-posix-comparison',
                          'error': message,
                          'report': str(report_path) if report_path else None,
                          'reportWritten': report_written,
                          'fixture': value.get('fixture')}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
