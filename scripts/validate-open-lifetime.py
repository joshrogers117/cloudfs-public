#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Validate retained open-file lifetime through two isolated CloudFS clients.

The script uses the supplied writable test filespace/folder only. It starts two
local cloudfsd processes with separate caches and mounts, reads bearer tokens from
private files under --state-dir, and writes a redacted report to its private run
directory. The namespace replacement is one direct PATCH request to the backend.
It checks cached vnode behavior, displaced target descriptor reads and writes,
destination identity and bytes, source-name reuse, and cleanup. It does not test
macOS smbfs's POSIX rename-overwrite request sequence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid
import urllib.parse


def pread_exact(fd, size, offset):
    chunks = []
    read = 0
    while read < size:
        chunk = os.pread(fd, size - read, offset + read)
        if not chunk:
            raise RuntimeError('descriptor returned a short read')
        chunks.append(chunk)
        read += len(chunk)
    return b''.join(chunks)


def pwrite_exact(fd, data, offset):
    written = 0
    while written < len(data):
        count = os.pwrite(fd, data[written:], offset + written)
        if count <= 0:
            raise RuntimeError('descriptor returned a short write')
        written += count
    return written


def private_text(path: Path, label: str) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f'{label} must be a regular private file')
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise RuntimeError(f'{label} permissions must exclude group and other access')
    value = path.read_text(encoding='utf-8').strip()
    if not value or any(char in value for char in '\r\n"\\'):
        raise RuntimeError(f'{label} has an invalid credential shape')
    return value


class Validation:
    def __init__(self, args):
        self.args = args
        if args.state_dir.is_symlink() or not args.state_dir.is_dir():
            raise RuntimeError('--state-dir must be an existing private directory')
        if stat.S_IMODE(args.state_dir.stat().st_mode) & 0o077:
            raise RuntimeError('--state-dir permissions must exclude group and other access')
        self.gateway = args.gateway.rstrip('/')
        self.space = '/v1/filespaces/' + urllib.parse.quote(args.filespace, safe='')
        self.run_id = secrets.token_hex(8)
        self.prefix = 'cflife-' + self.run_id
        self.run = (args.state_dir / ('run-' + self.run_id)).resolve()
        self.run.mkdir(mode=0o700, parents=False, exist_ok=False)
        os.chmod(self.run, 0o700)
        self.tokens = {
            'a': private_text(args.state_dir / 'a' / 'token', 'client A token'),
            'b': private_text(args.state_dir / 'b' / 'token', 'client B token'),
        }
        self.key_file = args.key_file
        if self.key_file is not None:
            private_text(self.key_file, 'filespace key')
        self.direct_clients = {'a': str(uuid.uuid4()), 'b': str(uuid.uuid4())}
        self.daemons = {}
        self.mounts = {}
        self.sockets = {}
        self.logs = {}
        self.open_fds = []
        self.handles = []
        self.created_ids = set()
        self.checks = {}
        self.compatibility_limitations = []
        if args.read_only_target:
            self.compatibility_limitations.append('diagnostic read-only target descriptor; target write lifetime was not tested')
        self.phase = 'preflight'

    def checked(self, name, details=None):
        self.checks[name] = {'pass': True, **(details or {})}
        print(name + ': PASS', flush=True)

    def request(self, client, method, path, body=None, expected=(200,)):
        token = self.tokens[client]
        command = [
            '/usr/bin/curl', '--silent', '--show-error', '--max-time', '40',
            '--config', '-', '--request', method, '--write-out', '\n%{http_code}',
            '--header', 'X-CloudFS-Client-ID: ' + self.direct_clients[client],
            self.gateway + self.space + path,
        ]
        if body is not None:
            command += ['--header', 'Content-Type: application/json', '--data-raw', json.dumps(body)]
        # Keep the bearer token out of argv, the environment, logs and output.
        cfg = f'header = "Authorization: Bearer {token}"\n'
        result = subprocess.run(command, input=cfg, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise RuntimeError(f'gateway request failed during {self.phase} (curl {result.returncode})')
        try:
            payload, status_text = result.stdout.rsplit('\n', 1)
            status = int(status_text)
        except (ValueError, TypeError):
            raise RuntimeError(f'gateway response was malformed during {self.phase}') from None
        if status not in expected:
            # Deliberately do not print the response body, which could contain
            # tenant-specific names or server diagnostics.
            try:
                code = str(json.loads(payload).get('error') or 'unspecified')[:80]
            except Exception:
                code = 'unspecified'
            raise RuntimeError(f'gateway returned HTTP {status} ({code}) during {self.phase}')
        if not payload:
            return None
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            raise RuntimeError(f'gateway returned invalid JSON during {self.phase}') from None

    def rpc(self, client, method, params=None, timeout=130):
        path = self.sockets[client]
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(timeout)
            sock.connect(str(path))
            message = {'jsonrpc': '2.0', 'id': 1, 'method': method,
                       'params': params or {'filespace': self.args.filespace}}
            sock.sendall((json.dumps(message) + '\n').encode())
            with sock.makefile('rb') as stream:
                response = json.loads(stream.readline(16 << 20))
        if 'error' in response:
            code = response['error'].get('code', 'unknown')
            raise RuntimeError(f'client {client} RPC {method} failed (code {code})')
        return response.get('result')

    def start_client(self, client):
        root = self.run / client
        root.mkdir(mode=0o700)
        mount = root / 'mount'
        mount.mkdir(mode=0o700)
        env_file = root / 'daemon.env'
        env_file.write_text('# Isolated open-file lifetime validation\n', encoding='utf-8')
        os.chmod(env_file, 0o600)
        sock = root / 'control.sock'
        cache = root / 'cache'
        log_path = root / 'cloudfsd.log'
        env = {key: value for key, value in os.environ.items() if not key.startswith('CLOUDFS_')}
        if self.args.smb_log:
            env['CLOUDFS_LOG_SMB'] = '1'
        if self.args.remote_presentation_ids:
            # This opt-in is independent of the identity-assertion exception.
            env['CLOUDFS_SMB_REMOTE_ID_EPOCHS'] = '1'
        command = [str(self.args.daemon.resolve()), '--env-file', str(env_file),
                   '--control-socket', str(sock), '--cache-dir', str(cache),
                   '--gateway', self.args.gateway, '--token-file', str((self.args.state_dir / client / 'token').resolve())]
        if client == 'b':
            # Force the read-after-replacement probe through a small independent
            # cache. The old inode is opened on B, while A creates and writes it.
            command += ['--cache-size', str(8 * 1024 * 1024), '--read-ahead-budget-mib', '8']
        if self.key_file is not None:
            command += ['--key-file', str(self.key_file.resolve()),
                        '--key-filespace', self.args.filespace,
                        '--key-gateway', self.args.gateway,
                        '--key-org', self.args.key_org]
        log = log_path.open('w', encoding='utf-8')
        os.chmod(log_path, 0o600)
        process = subprocess.Popen(command, env=env, stdout=log, stderr=log, close_fds=True)
        self.daemons[client] = process
        self.logs[client] = log
        self.mounts[client] = mount
        self.sockets[client] = sock
        deadline = time.monotonic() + 30
        while not sock.exists():
            if process.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError(f'client {client} daemon did not start; private log: {log_path}')
            time.sleep(0.05)
        self.rpc(client, 'mount', {'filespace': self.args.filespace, 'at': str(mount), 'name': 'CloudFS lifetime validation'})
        status = self.rpc(client, 'status', {'filespace': self.args.filespace})
        if status.get('mountPath') != str(mount) or status.get('connection') != 'connected':
            raise RuntimeError(f'client {client} did not mount the requested filespace')
        mount_rows = subprocess.run(['/sbin/mount'], capture_output=True, text=True, timeout=10, check=True).stdout.splitlines()
        if not any(f' on {mount} (smbfs' in row for row in mount_rows):
            raise RuntimeError(f'client {client} mount is not smbfs')
        return mount

    def flush(self, client):
        result = self.rpc(client, 'flush', {'filespace': self.args.filespace, 'path': '/', 'wait': True, 'timeoutMs': 120000}, timeout=130)
        pending_uploads = result.get('pendingUploads')
        pending_bytes = result.get('pendingBytes')
        if pending_uploads != 0 or pending_bytes != 0:
            raise RuntimeError(f'client {client} has pending writes at durability barrier')

    def list_items(self, client, parent):
        return self.request(client, 'GET', '/items?' + urllib.parse.urlencode({'parent': parent}))['items']

    def create_api_file(self, client, name):
        item = self.request(client, 'POST', '/items', {'parent': self.args.folder_id, 'name': name, 'size': 0}, expected=(201,))
        self.created_ids.add(item['id'])
        return item

    def acquire(self, client, item_id, access=1, share=7, ttl=90000):
        handle = str(uuid.uuid4())
        result = self.request(client, 'POST', '/open-handles',
                              {'action': 'acquire', 'id': item_id, 'handleId': handle,
                               'accessMask': access, 'shareMask': share, 'ttlMs': ttl})
        if result.get('granted'):
            self.handles.append((client, handle))
        return handle, result

    def close_handle(self, client, handle):
        self.request(client, 'POST', '/open-handles', {'action': 'close', 'handleId': handle})
        self.handles = [(owner, value) for owner, value in self.handles if not (owner == client and value == handle)]

    def remove_run_items(self):
        # The random run prefix is the fixture ownership boundary. Never delete
        # an item whose name does not carry this run's exact prefix.
        removed = 0
        def remove_children(parent):
            nonlocal removed
            for item in self.list_items('a', parent):
                if not item.get('name', '').startswith(self.prefix + '-'):
                    continue
                if item.get('isDir'):
                    remove_children(item['id'])
                self.request('a', 'DELETE', '/items/' + urllib.parse.quote(item['id'], safe=''), expected=(200, 404))
                removed += 1
        remove_children(self.args.folder_id)
        return removed

    def validate(self):
        self.phase = 'preflight'
        if sys.platform != 'darwin':
            raise RuntimeError('native SMB client validation requires macOS')
        if not self.args.daemon.is_file() or not os.access(self.args.daemon, os.X_OK):
            raise RuntimeError('--daemon must be an executable cloudfsd binary')
        url = urllib.parse.urlsplit(self.args.gateway)
        if url.scheme != 'https' or not url.netloc or url.username or url.password or url.query or url.fragment or url.path not in ('', '/'):
            raise RuntimeError('--gateway must be an HTTPS origin without credentials or path')
        if self.args.folder_relative.is_absolute() or '..' in self.args.folder_relative.parts:
            raise RuntimeError('--folder-relative must stay under the mount root')

        # Starting the daemons is the only local mount operation in this runner.
        for client in ('a', 'b'):
            self.start_client(client)
        folder_paths = {client: (self.mounts[client] / self.args.folder_relative).resolve() for client in ('a', 'b')}
        for client, folder in folder_paths.items():
            try:
                folder.relative_to(self.mounts[client].resolve())
            except ValueError:
                raise RuntimeError(f'client {client} test folder escaped the mount root') from None
            if not folder.is_dir():
                raise RuntimeError(f'client {client} cannot see the supplied test folder')
        self.flush('a'); self.flush('b')
        self.checked('two-isolated-smbfs-clients', {'filespace': self.args.filespace,
                    'folderRelative': str(self.args.folder_relative)})

        # Exercise real local open descriptors while a single backend namespace
        # transaction replaces the directory entry. Files are synthetic and
        # uniquely named; no existing file is opened for writing or replaced.
        self.phase = 'native-reader-backend-atomic-replacement'
        target_name = self.prefix + '-target.bin'
        source_name = self.prefix + '-source.bin'
        target_a = folder_paths['a'] / target_name
        target_b = folder_paths['b'] / target_name
        source_dir_name = self.prefix + '-source-dir'
        source_dir_a = folder_paths['a'] / source_dir_name
        source_dir_b = folder_paths['b'] / source_dir_name
        source_dir_a.mkdir(mode=0o700)
        self.flush('a')
        dir_deadline = time.monotonic() + 30
        observed_on_b = False
        while time.monotonic() < dir_deadline:
            try:
                observed_on_b = source_dir_name in os.listdir(folder_paths['b'])
            except OSError:
                observed_on_b = False
            if observed_on_b and source_dir_b.is_dir():
                break
            time.sleep(0.1)
        if not observed_on_b or not source_dir_b.is_dir():
            raise RuntimeError('client B did not enumerate the mounted source directory created by client A')
        source_dir_rows = [item for item in self.list_items('a', self.args.folder_id)
                           if item.get('name') == source_dir_name and item.get('isDir')]
        if len(source_dir_rows) != 1:
            raise RuntimeError('could not resolve the mounted source directory to exactly one backend item')
        source_dir = source_dir_rows[0]
        source_a = source_dir_a / source_name
        source_b = source_dir_b / source_name
        self.checked('nested-source-directory-created-and-discovered', {
            'createdThrough': 'mounted client A', 'enumeratedThrough': 'mounted client B',
            'backendIdResolvedAfterDiscovery': True, 'sourceDirectoryId': source_dir['id']})
        old_pattern = b'old-inode:' + self.run_id.encode() + b'\x00'
        new_pattern = b'new-inode:' + self.run_id.encode() + b'\xff'
        payload_size = 12 * 1024 * 1024
        old_bytes = (old_pattern * ((payload_size + len(old_pattern) - 1) // len(old_pattern)))[:payload_size]
        new_bytes = (new_pattern * ((payload_size + len(new_pattern) - 1) // len(new_pattern)))[:payload_size]
        for path, payload in ((target_a, old_bytes), (source_a, new_bytes)):
            with path.open('xb', buffering=0) as stream:
                stream.write(payload); os.fsync(stream.fileno())
        self.flush('a')
        old_target_identity_a = os.stat(target_a, follow_symlinks=False)
        old_fd = os.open(target_b, os.O_RDONLY if self.args.read_only_target else os.O_RDWR)
        self.open_fds.append(old_fd)
        source_fd = os.open(source_b, os.O_RDONLY)
        self.open_fds.append(source_fd)
        old_identity = os.fstat(old_fd)
        source_identity = os.fstat(source_fd)
        if (pread_exact(old_fd, 4096, 0) != old_bytes[:4096]
                or pread_exact(source_fd, 4096, 0) != new_bytes[:4096]):
            raise RuntimeError('client B could not cache and read both initial replacement vnodes')
        items = {item['name']: item for item in self.list_items('a', self.args.folder_id)}
        source_items = {item['name']: item for item in self.list_items('a', source_dir['id'])}
        target = items.get(target_name); source = source_items.get(source_name)
        if not target or not source or target.get('size') != len(old_bytes) or source.get('size') != len(new_bytes):
            raise RuntimeError('backend listing did not reflect the flushed synthetic files')
        old_handle, opened = self.acquire('a', target['id'], access=1, share=7)
        if not opened.get('granted'):
            raise RuntimeError('owner handle could not retain the replacement target')
        renamed = self.request('a', 'PATCH', '/items/' + urllib.parse.quote(source['id'], safe=''),
                               {'parent': self.args.folder_id, 'name': target_name, 'expectedVersion': source['version'],
                                'replace': {'id': target['id'], 'expectedVersion': target['version']}})
        if renamed.get('id') != source['id'] or renamed.get('name') != target_name:
            raise RuntimeError('backend replacement did not publish the source inode at the target path')

        retained = self.request('a', 'GET', '/items/' + urllib.parse.quote(target['id'], safe=''))
        blocks = self.request('a', 'GET', '/blocks/' + urllib.parse.quote(target['id'], safe=''))
        if not retained.get('deleted') or retained.get('id') != target['id'] or not blocks:
            raise RuntimeError('owner handle could not read the replaced target inode/manifest')
        block_rows = blocks.get('blocks', []) if isinstance(blocks, dict) else blocks
        block_count = len(block_rows) if isinstance(block_rows, list) else 0
        if block_count == 0:
            raise RuntimeError('retained old inode returned an empty or invalid block map')
        self.checked('owner-handle-retained-replaced-inode', {'retainedSize': retained.get('size'),
                    'retainedBlockCount': block_count})
        # Close the synthetic API handle before the final native descriptor
        # read. At that point the daemon's SMB open is the only intended remote
        # retention reference for the replaced inode.
        self.close_handle('a', old_handle)

        expected_hash = hashlib.sha256(new_bytes).hexdigest()
        def sees_replacement(client):
            path = (self.mounts[client] / self.args.folder_relative / target_name)
            try:
                return hashlib.sha256(path.read_bytes()).hexdigest() == expected_hash
            except OSError:
                return False
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not (sees_replacement('a') and sees_replacement('b')):
            time.sleep(0.1)
        if not sees_replacement('a') or not sees_replacement('b'):
            raise RuntimeError('mounted paths did not converge to the replacement source contents')
        target_identity_a = os.stat(target_a, follow_symlinks=False)
        target_identity_b = os.stat(target_b, follow_symlinks=False)
        displaced_identity_replaced_a = ((target_identity_a.st_dev, target_identity_a.st_ino)
                                         != (old_target_identity_a.st_dev, old_target_identity_a.st_ino))
        displaced_identity_replaced_b = ((target_identity_b.st_dev, target_identity_b.st_ino)
                                         != (old_identity.st_dev, old_identity.st_ino))
        if not displaced_identity_replaced_a or not displaced_identity_replaced_b:
            raise RuntimeError('fresh destination path reused the displaced target inode identity')
        self.checked('fresh-destination-identity-differs-from-displaced-target', {
            'clientAChanged': displaced_identity_replaced_a,
            'clientBChanged': displaced_identity_replaced_b,
            'displacedTargetA': {'device': old_target_identity_a.st_dev, 'inode': old_target_identity_a.st_ino},
            'freshTargetA': {'device': target_identity_a.st_dev, 'inode': target_identity_a.st_ino},
            'displacedTargetB': {'device': old_identity.st_dev, 'inode': old_identity.st_ino},
            'freshTargetB': {'device': target_identity_b.st_dev, 'inode': target_identity_b.st_ino}})
        moved_identity_preserved = ((target_identity_b.st_dev, target_identity_b.st_ino)
                                    == (source_identity.st_dev, source_identity.st_ino))
        if not moved_identity_preserved:
            if not self.args.allow_remote_presentation_id_change:
                raise RuntimeError('client B fresh destination pathname did not retain its cached moved source identity')
            self.compatibility_limitations.append('remote presentation identity changed during replacement')
        for client, source_path in (('a', source_a), ('b', source_b)):
            try:
                os.stat(source_path, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RuntimeError(f'client {client} still resolves the consumed source pathname')
        if pread_exact(source_fd, len(new_bytes), 0) != new_bytes:
            raise RuntimeError('cached source descriptor did not retain its original bytes after the move')
        self.checked('fresh-destination-bytes-and-moved-source-identity', {
            'pathIdentityMatchesCachedSource': moved_identity_preserved,
            'identityChangeAllowed': self.args.allow_remote_presentation_id_change,
            'bytes': len(new_bytes), 'sourceIdentity': {'device': source_identity.st_dev, 'inode': source_identity.st_ino},
            'destinationIdentityA': {'device': target_identity_a.st_dev, 'inode': target_identity_a.st_ino},
            'destinationIdentityB': {'device': target_identity_b.st_dev, 'inode': target_identity_b.st_ino}})
        self.checked('cached-source-vnode-retains-content-and-name-is-absent', {
            'cachedSourceBytes': len(new_bytes), 'sourceNameAbsentOnBothClients': True})

        # A read through the displaced target descriptor must still see its
        # original bytes after replacement.
        # Keep the tail untouched until the cold retained-inode probe below.
        # Reading it here would warm the macOS cache and invalidate that probe.
        old_original_prefix = pread_exact(old_fd, 4096, 0)
        if old_original_prefix != old_bytes[:4096]:
            raise RuntimeError('old target descriptor lost its original bytes after replacement')
        old_identity_after = os.fstat(old_fd)
        if ((old_identity_after.st_dev, old_identity_after.st_ino)
                != (old_identity.st_dev, old_identity.st_ino)):
            raise RuntimeError('old target descriptor lost its identity after replacement')
        if self.args.read_only_target:
            self.checked('old-target-descriptor-retains-original-bytes', {
                'targetDescriptorAccess': 'read-only', 'originalPrefixBytesRead': len(old_original_prefix),
                'writeLifetime': 'not tested'})
        else:
            old_tail = b'old-held-write:' + self.run_id.encode()
            tail_offset = len(old_bytes)
            pwrite_exact(old_fd, old_tail, tail_offset)
            os.fsync(old_fd)
            if pread_exact(old_fd, len(old_tail), tail_offset) != old_tail:
                raise RuntimeError('old target descriptor could not read its post-replacement write')
            self.flush('b')
            if not sees_replacement('a') or not sees_replacement('b'):
                raise RuntimeError('writing through the old target descriptor changed the fresh destination')
            self.checked('old-target-descriptor-remains-readable-and-writable', {
                'targetDescriptorAccess': 'read-write',
                'oldTargetIdentity': {'device': old_identity.st_dev, 'inode': old_identity.st_ino},
                'originalPrefixBytesRead': len(old_original_prefix), 'writtenBytes': len(old_tail),
                'freshDestinationUnchanged': True})

        # Reuse the consumed source name. Client B has a cached vnode and must
        # resolve the new directory entry instead of following a stale alias.
        reuse_bytes = b'reused-source-name:' + self.run_id.encode() + b'\x00'
        with source_a.open('xb', buffering=0) as stream:
            stream.write(reuse_bytes)
            os.fsync(stream.fileno())
        self.flush('a')
        reuse_deadline = time.monotonic() + 30
        def sees_reused_source(client):
            path = self.mounts[client] / self.args.folder_relative / source_dir_name / source_name
            try:
                return path.read_bytes() == reuse_bytes
            except OSError:
                return False
        while time.monotonic() < reuse_deadline and not (sees_reused_source('a') and sees_reused_source('b')):
            time.sleep(0.1)
        if not sees_reused_source('a') or not sees_reused_source('b'):
            raise RuntimeError('source-name reuse resolved to stale or incorrect bytes')
        reused_info = os.stat(source_b, follow_symlinks=False)
        target_info_after_reuse = os.stat(target_b, follow_symlinks=False)
        if ((reused_info.st_dev, reused_info.st_ino)
                == (target_info_after_reuse.st_dev, target_info_after_reuse.st_ino)
                or not sees_replacement('a') or not sees_replacement('b')):
            raise RuntimeError('source-name reuse aliased the replacement destination')
        current = {item['name']: item for item in self.list_items('a', self.args.folder_id)}
        current_sources = {item['name']: item for item in self.list_items('a', source_dir['id'])}
        if (current.get(target_name, {}).get('id') != source['id']
                or not current_sources.get(source_name)
                or current_sources[source_name].get('id') == source['id']):
            raise RuntimeError('backend identities did not distinguish moved source from reused source name')
        self.flush('a'); self.flush('b')
        self.checked('source-name-reuse-does-not-follow-stale-alias', {
            'reusedBytes': len(reuse_bytes), 'movedSourceIdAtDestination': source['id'],
            'reusedSourceId': current_sources[source_name]['id'],
            'reusedIdentity': {'device': reused_info.st_dev, 'inode': reused_info.st_ino},
            'destinationIdentity': {'device': target_info_after_reuse.st_dev, 'inode': target_info_after_reuse.st_ino}})
        # Let replacement downloads/read-ahead finish before the tail baseline.
        settle_deadline = time.monotonic() + 30
        status_before_tail = self.rpc('b', 'status', {'filespace': self.args.filespace})
        while (status_before_tail.get('storage') or {}).get('activeRequests', 0) and time.monotonic() < settle_deadline:
            time.sleep(0.1)
            status_before_tail = self.rpc('b', 'status', {'filespace': self.args.filespace})
        if (status_before_tail.get('storage') or {}).get('activeRequests', 0):
            raise RuntimeError('client B storage downloads did not settle before the old-inode tail probe')
        storage_before_tail = status_before_tail.get('storage') or {}
        requests_before_tail = storage_before_tail.get('requests', 0)
        tail_offset = len(old_bytes) - 64 * 1024
        retained_tail = os.pread(old_fd, len(old_bytes) - tail_offset, tail_offset)
        if retained_tail != old_bytes[tail_offset:]:
            raise RuntimeError('already-open native descriptor could not read the old inode tail after replacement')
        deadline = time.monotonic() + 15
        storage_after_tail = storage_before_tail
        while time.monotonic() < deadline:
            status_after_tail = self.rpc('b', 'status', {'filespace': self.args.filespace})
            storage_after_tail = status_after_tail.get('storage') or {}
            if storage_after_tail.get('requests', 0) > requests_before_tail:
                break
            time.sleep(0.1)
        if storage_after_tail.get('requests', 0) <= requests_before_tail:
            raise RuntimeError('old-inode tail read succeeded without a new object-storage request on client B')
        self.checked('same-path-replacement-visible-on-both-clients', {'newBytes': len(new_bytes)})
        self.checked('already-open-native-descriptor-retains-old-bytes', {'tailBytesReadAfterReplacement': len(retained_tail),
                    'oldFileBytes': len(old_bytes), 'clientBStorageRequestsBeforeTail': requests_before_tail,
                    'clientBStorageRequestsAfterTail': storage_after_tail.get('requests')})
        os.close(old_fd); self.open_fds.remove(old_fd)
        os.close(source_fd); self.open_fds.remove(source_fd)
        self.flush('a'); self.flush('b')

        # Direct API sharing checks use distinct client IDs and the two private
        # tokens, independently of the random IDs used by each daemon process.
        self.phase = 'cross-client-share-modes'
        shared = self.create_api_file('a', self.prefix + '-sharing.bin')
        reader, grant = self.acquire('a', shared['id'], access=1, share=5)
        if not grant.get('granted'):
            raise RuntimeError('could not acquire test reader for share-mode check')
        writer, denied = self.acquire('b', shared['id'], access=2, share=7)
        if denied.get('granted') or denied.get('reason') != 'sharing_violation':
            raise RuntimeError('cross-client write was not denied by the reader share mask')
        self.close_handle('a', reader)
        writer, grant = self.acquire('b', shared['id'], access=2, share=7)
        if not grant.get('granted'):
            raise RuntimeError('cross-client write did not succeed after reader closed')
        self.close_handle('b', writer)
        self.checked('cross-client-sharing-restrictions')

        self.phase = 'batch-renew-close-expiry'
        batch_file = self.create_api_file('a', self.prefix + '-batch.bin')
        batch = [self.acquire('a', batch_file['id'])[0] for _ in range(3)]
        renewed = self.request('a', 'POST', '/open-handles', {'action': 'renew-batch', 'handles': batch, 'ttlMs': 90000})
        results = renewed.get('handles', [])
        if len(results) != len(batch) or any(not item.get('granted') for item in results):
            raise RuntimeError('batch renewal did not grant every owner handle')
        self.checked('batch-renewal', {'handleCount': len(results)})
        for handle in batch:
            self.close_handle('a', handle)
        if self.request('a', 'GET', '/items/' + urllib.parse.quote(batch_file['id'], safe='')).get('deleted'):
            raise RuntimeError('unexpected tombstone before explicit close')
        self.checked('batch-close')

        expiring = self.create_api_file('a', self.prefix + '-expiry.bin')
        expiring_handle, expiry_grant = self.acquire('a', expiring['id'], ttl=1000)
        if not expiry_grant.get('granted'):
            raise RuntimeError('could not acquire minimum-TTL expiry handle')
        self.request('a', 'DELETE', '/items/' + urllib.parse.quote(expiring['id'], safe=''))
        self.request('a', 'GET', '/items/' + urllib.parse.quote(expiring['id'], safe=''))
        time.sleep(1.4)
        expired_item = self.request('a', 'GET', '/items/' + urllib.parse.quote(expiring['id'], safe=''), expected=(404,))
        expiry_renewal = self.request('a', 'POST', '/open-handles',
                                      {'action': 'renew', 'handleId': expiring_handle, 'ttlMs': 90000})
        if expiry_renewal.get('granted'):
            raise RuntimeError('expired owner handle renewed successfully')
        self.handles = [(owner, value) for owner, value in self.handles if value != expiring_handle]
        self.checked('bounded-handle-expiry')

        self.phase = 'cleanup'
        self.flush('a'); self.flush('b')
        self.stop_clients()
        removed = self.remove_run_items()
        self.checked('synthetic-fixture-cleanup', {'removedRunItems': removed})
        result = 'PASS_WITH_LIMITATIONS' if self.compatibility_limitations else 'PASS'
        report = {
            'result': result, 'compatibilityLimitations': self.compatibility_limitations,
            'filespace': self.args.filespace,
            'testFolderId': self.args.folder_id, 'runId': self.run_id,
            'checks': self.checks,
            'scope': (('Read-only diagnostic replacement probe; target write lifetime was not tested. '
                       'The namespace change uses one PATCH /items/:id transaction with separate SMB caches.')
                      if self.args.read_only_target else
                      ('Strict remote replacement assertions use one PATCH /items/:id transaction in the supplied '
                       'test folder, with separate SMB caches on two clients.')
                      + ' This does not test the separate Apple smbfs POSIX os.replace delete-then-rename request sequence.'),
            'targetDescriptorAccess': 'read-only' if self.args.read_only_target else 'read-write',
            'targetWriteLifetime': 'not tested' if self.args.read_only_target else 'passed',
            'remotePresentationIdsEnabled': self.args.remote_presentation_ids,
            'limitation': 'ACL revocation was not changed because this runner does not accept a workspace-admin credential.',
            'localEvidence': str(self.run),
        }
        report_path = self.run / 'report.json'
        fd = os.open(report_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(report, stream, indent=2, sort_keys=True); stream.write('\n')
        print('RESULT: ' + result)
        print('REPORT: ' + str(report_path))
        return report_path

    def stop_clients(self):
        for client, process in list(self.daemons.items()):
            try:
                if process.poll() is None:
                    try:
                        self.rpc(client, 'unmount', {'filespace': self.args.filespace, 'force': False}, timeout=40)
                    except Exception:
                        pass
                    if process.poll() is None:
                        process.send_signal(signal.SIGTERM)
                        try:
                            process.wait(timeout=130)
                        except subprocess.TimeoutExpired:
                            raise RuntimeError(f'client {client} did not stop gracefully; refusing to force-kill it')
            finally:
                self.logs[client].close()
        self.daemons.clear()

    def cleanup(self):
        for fd in self.open_fds:
            try: os.close(fd)
            except OSError: pass
        self.open_fds.clear()
        for client, handle in list(self.handles):
            try: self.close_handle(client, handle)
            except Exception: pass
        try: self.stop_clients()
        except Exception as error:
            print('CLEANUP: ' + str(error), file=sys.stderr)
        try:
            removed = self.remove_run_items()
            if removed:
                print('CLEANUP: removed ' + str(removed) + ' run-owned remote items', file=sys.stderr)
        except Exception as error:
            print('CLEANUP: remote fixture removal failed (' + type(error).__name__ + ')', file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gateway', required=True, help='HTTPS gateway origin, with no path or credentials')
    parser.add_argument('--filespace', required=True, help='Provided disposable test filespace ID')
    parser.add_argument('--folder-id', required=True, help='Existing writable test folder inode ID')
    parser.add_argument('--folder-relative', type=Path, default=Path('.'), help='Same existing folder path below each mount')
    parser.add_argument('--daemon', required=True, type=Path, help='Built cloudfsd executable')
    parser.add_argument('--state-dir', required=True, type=Path, help='Private directory containing a/token and b/token')
    parser.add_argument('--allow-remote-presentation-id-change', action='store_true',
                        help='Allow a changed mounted st_ino after replacement and report PASS_WITH_LIMITATIONS')
    parser.add_argument('--key-file', type=Path, help='Optional private filespace key file')
    parser.add_argument('--key-org', help='Authenticated organization ID for an explicit local key file')
    parser.add_argument('--read-only-target', action='store_true',
                        help='Run a diagnostic replacement probe with a read-only target descriptor; write lifetime is not tested')
    parser.add_argument('--smb-log', action='store_true', help='Record SMB diagnostics in the private run directory')
    parser.add_argument('--remote-presentation-ids', action='store_true',
                        help='Set CLOUDFS_SMB_REMOTE_ID_EPOCHS=1 for the spawned daemons')
    args = parser.parse_args()
    if args.key_file and not args.key_org:
        parser.error('--key-org is required when --key-file is supplied')
    validation = None
    try:
        validation = Validation(args)
        validation.validate()
    except Exception as error:
        print('RESULT: FAIL', file=sys.stderr)
        print('ERROR: ' + str(error), file=sys.stderr)
        if validation is not None:
            print('LOCAL_EVIDENCE: ' + str(validation.run), file=sys.stderr)
        return 1
    finally:
        if validation is not None:
            validation.cleanup()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
