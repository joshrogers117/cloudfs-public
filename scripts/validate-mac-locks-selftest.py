#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Local kernel contract test for validate-mac-locks. No CloudFS mounts touched.

Build the C helper first; run with --helper /tmp/validate-mac-locks.
This proves the probe and its result classification on the local filesystem.
It is NOT a multi-Mac or live-backend test; reuse the helper on both Macs for that.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--helper', default='/tmp/validate-mac-locks')
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    checks = []
    active = []
    with tempfile.TemporaryDirectory(prefix='cloudfs-editor-validation-lock-helper-') as directory:
        root = Path(directory)
        target = root / 'ranges.bin'
        target.write_bytes(b'fixture\n' * 2048)
        before = target.read_bytes()

        def check(name, condition, details=None):
            checks.append({'name': name, 'passed': bool(condition), 'details': details})
            if not condition:
                raise AssertionError(name)

        def probe(mode, offset, expected, name, status=0):
            result = subprocess.run([args.helper, 'probe', str(target), mode, str(offset), '4096',
                                     '--expect', expected], capture_output=True, text=True, timeout=10)
            data = json.loads(result.stdout)
            check(name, result.returncode == status and data['expectationMatched'] == (status == 0), data)

        def hold(mode, suffix):
            ready, release = root / (suffix + '.ready'), root / (suffix + '.release')
            process = subprocess.Popen([args.helper, 'hold', str(target), mode, '0', '4096',
                                        '--seconds', '20', '--ready', str(ready), '--release', str(release)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            active.append(process)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and process.poll() is None and not ready.exists():
                time.sleep(0.02)
            data = json.loads(ready.read_text()) if ready.exists() else {}
            check(suffix + ' acquired', data.get('phase') == 'held' and data.get('acquired') is True, data)
            return process, release

        try:
            process, release = hold('shared', 'shared-holder')
            probe('shared', 0, 'acquired', 'shared locks coexist')
            probe('exclusive', 0, 'blocked', 'shared blocks overlapping exclusive')
            probe('exclusive', 8192, 'acquired', 'disjoint exclusive coexists with shared')
            release.touch()
            output, error = process.communicate(timeout=5)
            check('shared explicit release', process.returncode == 0 and json.loads(output.splitlines()[-1])['phase'] == 'released', error)
            probe('exclusive', 0, 'acquired', 'exclusive succeeds after shared release')
            process, release = hold('exclusive', 'exclusive-holder')
            probe('shared', 0, 'blocked', 'exclusive blocks overlapping shared')
            probe('exclusive', 0, 'blocked', 'exclusive blocks overlapping exclusive')
            probe('shared', 8192, 'acquired', 'disjoint shared coexists with exclusive')
            probe('exclusive', 8192, 'acquired', 'disjoint exclusive coexists with exclusive')
            probe('shared', 0, 'acquired', 'incorrect expectation fails', status=1)
            process.send_signal(signal.SIGTERM)
            output, error = process.communicate(timeout=5)
            final = json.loads(output.splitlines()[-1])
            check('SIGTERM releases cleanly', process.returncode == 0 and final['phase'] == 'released' and final['signal'] == signal.SIGTERM, error)
            probe('exclusive', 0, 'acquired', 'exclusive succeeds after SIGTERM')
            process, _ = hold('exclusive', 'crash-holder')
            process.kill()
            process.communicate(timeout=5)
            probe('exclusive', 0, 'acquired', 'kernel releases on holder crash')
            blocked_path = subprocess.run([args.helper, 'probe', '/dev/null', 'shared', '0', '1', '--expect', 'blocked'], capture_output=True, text=True)
            check('rejects outside fixture', blocked_path.returncode == 2)
            missing = subprocess.run([args.helper, 'probe', str(root / 'missing'), 'shared', '0', '1', '--expect', 'blocked'], capture_output=True, text=True)
            check('missing file never counts as blocked pass', missing.returncode == 2)
            target.chmod(0)
            try:
                denied = subprocess.run([args.helper, 'probe', str(target), 'exclusive', '0', '4096', '--expect', 'blocked'], capture_output=True, text=True)
                denied_json = json.loads(denied.stdout)
                check('open denial never counts as blocked lock', denied.returncode == 2 and denied_json['phase'] == 'open_failed' and not denied_json['expectationMatched'], denied_json)
            finally:
                target.chmod(0o600)
            check('lock probes preserve fixture bytes', before == target.read_bytes())
        finally:
            for process in active:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
    report = {'passed': all(item['passed'] for item in checks), 'scope': 'local kernel helper self-test; not CloudFS or multi-Mac validation',
              'helper': os.path.realpath(args.helper), 'checks': checks}
    encoded = json.dumps(report, indent=2) + '\n'
    if args.out:
        args.out.write_text(encoded)
    print(encoded, end='')


if __name__ == '__main__':
    main()
