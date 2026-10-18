#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compare flock(2) and fcntl.lockf(2) across independent processes.

Run once per explicitly supplied mounted volume and compare the JSON reports:
  python3 compare-mounted-locking.py --label lucidlink --mount /Volumes/LucidLink --report /tmp/lucidlink-locks.json
  python3 compare-mounted-locking.py --label cloudfs --mount /Volumes/CloudFS --report /tmp/cloudfs-locks.json

All changes stay in a newly created UUID directory at the mount root. The
fixture directory is intentionally retained, including on failure. Unsupported
lock methods are reported as capabilities and do not fail the comparison.
"""
import argparse
import errno
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

OP_TIMEOUT_SECONDS = 8
CHILD_TIMEOUT_SECONDS = 5
UNSUPPORTED_ERRNOS = {
    getattr(errno, name) for name in ('ENOTSUP', 'EOPNOTSUPP', 'ENOSYS')
    if hasattr(errno, name)
}
SCRIPT_PATH = Path(__file__).resolve()
O_NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)


class CheckFailure(RuntimeError):
    pass


class OperationTimeout(TimeoutError):
    pass


def bounded(label, seconds=OP_TIMEOUT_SECONDS):
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


def lock_operation(kind, fd, acquire):
    if kind == 'flock':
        operation = (fcntl.LOCK_EX | fcntl.LOCK_NB) if acquire else fcntl.LOCK_UN
        fcntl.flock(fd, operation)
    elif kind == 'lockf':
        operation = (fcntl.LOCK_EX | fcntl.LOCK_NB) if acquire else fcntl.LOCK_UN
        fcntl.lockf(fd, operation, 1, 0, os.SEEK_SET)
    else:
        raise ValueError('unknown lock kind')


def child_probe(kind, path):
    try:
        fd = os.open(path, os.O_RDWR | O_NOFOLLOW)
    except OSError as exc:
        print(json.dumps({'state': 'ERROR', 'errno': exc.errno}))
        return 2
    try:
        try:
            lock_operation(kind, fd, acquire=True)
        except OSError as exc:
            if exc.errno in UNSUPPORTED_ERRNOS:
                print(json.dumps({'state': 'UNSUPPORTED', 'errno': exc.errno}))
                return 0
            if exc.errno in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                print(json.dumps({'state': 'BLOCKED'}))
                return 0
            print(json.dumps({'state': 'ERROR', 'errno': exc.errno}))
            return 2
        else:
            try:
                lock_operation(kind, fd, acquire=False)
            except OSError as exc:
                print(json.dumps({'state': 'ERROR', 'errno': exc.errno, 'phase': 'unlock'}))
                return 2
            print(json.dumps({'state': 'ACQUIRED'}))
            return 0
    finally:
        os.close(fd)


def probe_child(kind, path):
    try:
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), '--_probe', kind, str(path)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=CHILD_TIMEOUT_SECONDS, check=False,
            env={key: value for key, value in os.environ.items() if not key.startswith('CLOUDFS_')},
        )
    except subprocess.TimeoutExpired:
        return {'state': 'ERROR', 'error': 'child exceeded bounded wait'}
    try:
        response = json.loads(result.stdout.strip())
    except json.JSONDecodeError:
        response = {'state': 'ERROR', 'error': 'child returned malformed response'}
    if result.returncode != 0 and response.get('state') != 'ERROR':
        response = {'state': 'ERROR', 'error': f'child exit code {result.returncode}'}
    return response


class LockComparison:
    def __init__(self, mount, label):
        self.mount = mount
        self.label = label
        self.run_id = uuid.uuid4().hex
        self.directory_name = f'lock-compare-{self.run_id}'
        self.fixture_dir = mount / self.directory_name
        self.methods = []

    def run_method(self, kind):
        path = self.fixture_dir / f'{kind}.bin'
        fd = None
        outcome = {'method': kind, 'capability': 'supported', 'pass': False}
        try:
            with bounded(f'{kind} parent file open'):
                fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | O_NOFOLLOW, 0o600)
                os.write(fd, b'lock-comparison\n')
                os.fsync(fd)
            try:
                with bounded(f'{kind} parent lock acquisition'):
                    lock_operation(kind, fd, acquire=True)
            except OSError as exc:
                if exc.errno in UNSUPPORTED_ERRNOS:
                    outcome.update({'capability': 'unsupported', 'unsupportedAt': 'parent-acquire',
                                    'errno': exc.errno, 'pass': True})
                    return outcome
                outcome.update({'error': f'parent acquire failed with errno {exc.errno}'})
                return outcome

            conflict = probe_child(kind, path)
            outcome['conflictProbe'] = conflict
            if conflict.get('state') == 'UNSUPPORTED':
                outcome.update({'capability': 'partial-or-inconsistent',
                                'unsupportedAt': 'child-conflict-probe',
                                'errno': conflict.get('errno'),
                                'error': 'parent lock succeeded but child conflict probe reported unsupported'})
                return outcome
            if conflict.get('state') == 'ERROR':
                outcome['error'] = f"conflict probe failed: {conflict.get('error') or conflict.get('errno')}"
                return outcome
            if conflict.get('state') != 'BLOCKED':
                outcome['error'] = 'second process acquired a lock while parent held it'
                return outcome

            try:
                with bounded(f'{kind} parent unlock'):
                    lock_operation(kind, fd, acquire=False)
            except OSError as exc:
                if exc.errno in UNSUPPORTED_ERRNOS:
                    outcome.update({'capability': 'partial-or-inconsistent',
                                    'unsupportedAt': 'parent-unlock', 'errno': exc.errno,
                                    'error': 'parent lock succeeded but unlock reported unsupported'})
                else:
                    outcome['error'] = f'parent unlock failed with errno {exc.errno}'
                return outcome
            released = probe_child(kind, path)
            outcome['releaseProbe'] = released
            if released.get('state') == 'UNSUPPORTED':
                outcome.update({'capability': 'partial-or-inconsistent',
                                'unsupportedAt': 'child-release-probe',
                                'errno': released.get('errno'),
                                'error': 'parent lock and unlock succeeded but child release probe reported unsupported'})
                return outcome
            if released.get('state') == 'ERROR':
                outcome['error'] = f"release probe failed: {released.get('error') or released.get('errno')}"
                return outcome
            outcome['pass'] = released.get('state') == 'ACQUIRED'
            if not outcome['pass']:
                outcome['error'] = 'second process remained blocked after parent unlock'
            return outcome
        except Exception as exc:
            outcome['error'] = str(exc).replace('\n', ' ')[:240] or type(exc).__name__
            return outcome
        finally:
            if fd is not None:
                try:
                    with bounded(f'{kind} parent file close'):
                        os.close(fd)
                except OSError:
                    pass

    def run(self):
        with bounded('mount root identity'):
            root_info = self.mount.stat()
            os.mkdir(self.fixture_dir, 0o700)
            fixture_info = self.fixture_dir.stat(follow_symlinks=False)
            fixture_is_symlink = self.fixture_dir.is_symlink()
            fixture_is_directory = self.fixture_dir.is_dir()
            fixture_resolved = self.fixture_dir.resolve(strict=True)
        if (fixture_is_symlink or not fixture_is_directory
                or fixture_info.st_dev != root_info.st_dev or fixture_resolved.parent != self.mount):
            raise CheckFailure('fixture directory changed mount identity')
        # Each method gets an independent file and runs even if the other errors.
        for kind in ('flock', 'lockf'):
            outcome = self.run_method(kind)
            self.methods.append(outcome)
            print(f"{kind}: {'PASS' if outcome['pass'] else 'FAIL'} ({outcome['capability']})", flush=True)
        passed = all(item['pass'] for item in self.methods)
        return {
            'result': 'PASS' if passed else 'FAIL',
            'label': self.label,
            'mount': str(self.mount),
            'methods': self.methods,
            'protocol': 'Independent child process probes nonblocking conflict and acquisition after parent unlock.',
            'unsupportedPolicy': 'Unsupported is a capability result and does not fail the comparison.',
            'fixture': {'path': str(self.fixture_dir), 'directory': self.directory_name,
                        'cleanup': 'none; fixture directory is retained, including on failure'},
        }


def validate_paths(mount_arg, report_arg):
    mount = Path(mount_arg)
    if (not mount.is_absolute() or mount.is_symlink() or not mount.is_dir()
            or mount.resolve(strict=True) != mount or mount == Path('/') or not os.path.ismount(mount)):
        raise CheckFailure('--mount must be an existing canonical mounted volume and cannot be /')
    report = Path(report_arg)
    if not report.is_absolute():
        raise CheckFailure('--report must be absolute')
    if report.parent.is_symlink() or not report.parent.is_dir() or report.parent.resolve(strict=True) != report.parent:
        raise CheckFailure('--report parent must be an existing canonical directory')
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
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW, 0o600)
    try:
        data = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
        offset = 0
        while offset < len(data):
            with bounded('report write'):
                count = os.write(fd, data[offset:])
            if count <= 0:
                raise OSError('report write made no progress')
            offset += count
        with bounded('report fsync'):
            os.fsync(fd)
    finally:
        os.close(fd)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) == 3 and argv[0] == '--_probe':
        return child_probe(argv[1], argv[2])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    parser.add_argument('--mount', required=True)
    parser.add_argument('--report', required=True)
    args = parser.parse_args(argv)
    started = time.monotonic()
    try:
        with bounded('mount and report preflight', 10):
            mount, report_path = validate_paths(args.mount, args.report)
        comparison = LockComparison(mount, args.label)
        value = comparison.run()
        value['elapsedMs'] = round((time.monotonic() - started) * 1000)
        write_report(report_path, value)
        print(json.dumps({'result': value['result'], 'report': str(report_path),
                          'fixture': value['fixture']['path']}, sort_keys=True))
        return 0 if value['result'] == 'PASS' else 1
    except Exception as exc:
        message = str(exc).replace('\n', ' ')[:300] or type(exc).__name__
        value = {'result': 'FAIL', 'label': args.label, 'mount': args.mount,
                 'elapsedMs': round((time.monotonic() - started) * 1000), 'error': message}
        try:
            if 'report_path' in locals():
                write_report(report_path, value)
        except OSError:
            pass
        print(json.dumps(value, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
