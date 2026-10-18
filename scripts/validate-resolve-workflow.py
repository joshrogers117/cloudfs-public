#!/usr/bin/env python3
"""Exercise Resolve's real import/edit/export/render path on a mounted test folder.

Run with ResolvePython while Resolve is open. Uses the vendor scripting API;
never changes an existing project, application preferences, or project library.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import time
import uuid

OWNED_ROOT = 'cloudfs-editor-validation-20261015'


def isolated_scope(root, control_socket, filespace):
    """Lexical-only scope validation; safe for self-tests without a live mount."""
    if control_socket is None:
        return None
    assert filespace == 'edit1', 'Isolated mode is confined to Edit 1'
    match = re.fullmatch(r'(/private/tmp/cloudfs-collaboration-[A-Za-z0-9][A-Za-z0-9_-]{5,63})/(?:control|d)\.sock', str(control_socket))
    assert match, 'Control socket must be inside a unique canonical private collaboration directory'
    base = Path(match.group(1))
    assert root == base / 'mount' / OWNED_ROOT, 'Isolated mode requires the exact owned fixture child'
    return base


def status_matches_mount(status, mount, filespace='edit1'):
    return isinstance(status, dict) and status.get('filespace') == filespace and \
        status.get('mountPath') == str(mount) and status.get('connection') == 'connected'


def synchronized_status(status, mount, filespace='edit1'):
    return status_matches_mount(status, mount, filespace) and \
        status.get('pendingUploads') == 0 and status.get('pendingBytes') == 0


def validate_isolated_filesystem(base, root, control_socket):
    info = base.lstat()
    assert stat.S_ISDIR(info.st_mode) and base.resolve() == base and not base.is_symlink(), 'Isolated directory must be canonical'
    assert info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0, 'Isolated directory must be private and owned by this user'
    for path in (base / 'mount', root):
        assert path.is_dir() and not path.is_symlink() and path.resolve() == path, 'Isolated mount and fixture must be canonical directories'
    info = control_socket.lstat()
    assert stat.S_ISSOCK(info.st_mode) and not control_socket.is_symlink() and control_socket.resolve() == control_socket, 'Expected a canonical local Unix control socket'
    assert info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0, 'Control socket must be private and owned by this user'


def guard_self_test():
    base = Path('/private/tmp/cloudfs-collaboration-ABC123')
    root = base / 'mount' / OWNED_ROOT
    count = 0
    assert isolated_scope(root, None, 'edit1') is None
    count += 1
    for name in ('control.sock', 'd.sock'):
        assert isolated_scope(root, base / name, 'edit1') == base
        count += 1
    invalid = [
        (root, base / 'd.sock', 'other'),
        (Path('/Users/example-user/cloudfs/edit1') / OWNED_ROOT, base / 'd.sock', 'edit1'),
        (root, Path('/tmp/cloudfs-collaboration-ABC123/d.sock'), 'edit1'),
        (root, Path('/private/tmp/cloudfs-collaboration-x/d.sock'), 'edit1'),
        (root, Path('/private/tmp/cloudfs-collaboration-OTHER1/d.sock'), 'edit1'),
        (base / 'mount' / 'cloudfs-editor-validation-other', base / 'd.sock', 'edit1'),
        (base / 'mount' / OWNED_ROOT / '..' / OWNED_ROOT, base / 'd.sock', 'edit1'),
        (root, base / '..' / 'd.sock', 'edit1'),
        (root, Path.home() / 'Library/Application Support/cloudfs/d.sock', 'edit1'),
    ]
    for values in invalid:
        try:
            isolated_scope(*values)
        except AssertionError:
            count += 1
        else:
            raise AssertionError('Unsafe isolated scope accepted')
    mounted = {'filespace': 'edit1', 'connection': 'connected', 'mountPath': str(base / 'mount')}
    assert status_matches_mount(mounted, base / 'mount')
    count += 1
    for bad in ({**mounted, 'filespace': 'other'}, {**mounted, 'connection': 'disconnected'},
                {**mounted, 'mountPath': '/Users/example-user/cloudfs/edit1'}, {}, []):
        assert not status_matches_mount(bad, base / 'mount')
        count += 1
    synced = {**mounted, 'pendingUploads': 0, 'pendingBytes': 0}
    assert synchronized_status(synced, base / 'mount')
    count += 1
    for bad in ({**synced, 'pendingUploads': 1}, {**synced, 'pendingBytes': 1},
                {**synced, 'connection': 'disconnected'}, mounted, {}):
        assert not synchronized_status(bad, base / 'mount')
        count += 1
    print(json.dumps({'result': 'PASS', 'checks': count, 'scope': 'Pure scope/status guards; no filesystem, socket, credentials or Resolve API access'}))


def main():
    if not __debug__:
        raise RuntimeError('Safety checks require Python without -O')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--filespace', default='edit1')
    parser.add_argument('--control-socket', type=Path,
                        help='Optional isolated-host socket inside /private/tmp/cloudfs-collaboration-*/; never a credential argument')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        guard_self_test()
        return
    if args.root is None or args.output is None:
        parser.error('--root and --output are required for a live workflow')
    isolated = isolated_scope(args.root, args.control_socket, args.filespace)
    if isolated:
        validate_isolated_filesystem(isolated, args.root, args.control_socket)
    root = args.root.resolve()
    assert root.name.startswith('cloudfs-editor-validation-'), 'Use an owned test directory'
    assert not args.output.exists(), 'Evidence output exists'
    source = root / 'CloudFS-Test-1080p.mov'
    assert source.is_file()
    control_socket = args.control_socket or Path.home() / 'Library/Application Support/cloudfs/d.sock'
    report = {'result': 'RUNNING', 'root': str(root), 'checks': {}, 'createdProjects': [],
              'target': {'mode': 'isolated-signed-release-daemon' if isolated else 'standard-app-daemon',
                         'controlSocket': str(control_socket), 'installedNativeAppRestorationVerified': False}}
    if isolated:
        report['target']['signatureVerification'] = 'Required separately by launch orchestration; not inferred from socket status'
    args.output.parent.mkdir(parents=True, exist_ok=True)

    def save():
        args.output.write_text(json.dumps(report, indent=2) + '\n')

    def check(name, value=True):
        report['checks'][name] = value
        save()
        print(name + ': PASS', flush=True)

    def rpc(method):
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(130)
            sock.connect(str(control_socket))
            sock.sendall((json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method,
                                      'params': {'filespace': args.filespace, 'path': '/',
                                                 'wait': True, 'timeoutMs': 120000}}) + '\n').encode())
            response = json.loads(sock.makefile().readline())
            assert 'error' not in response, response.get('error')
            return response['result']

    try:
        if isolated:
            status = rpc('status')
            assert synchronized_status(status, isolated / 'mount'), 'Daemon must report the exact connected isolated Edit 1 mount with zero pending writes'
            inventory = subprocess.check_output(['/sbin/mount'], text=True)
            assert re.search(r' on ' + re.escape(str(isolated / 'mount')) + r' \(smbfs[,)]', inventory), 'Expected an SMB filesystem at the isolated mount'
            report['target']['mountPath'] = status['mountPath']
            report['target']['engineVersion'] = rpc('system.version')
            check('isolatedMountAndControlSocketMatch', True)
        import DaVinciResolveScript
        resolve = DaVinciResolveScript.scriptapp('Resolve')
        assert resolve, 'Resolve scripting connection unavailable'
        report['resolveVersion'] = resolve.GetVersionString()
        manager = resolve.GetProjectManager()
        current = manager.GetCurrentProject()
        # Do not close or save a user's current editing session.
        assert not current or current.GetName() == 'Untitled Project', 'Close the existing project first'
        name = 'CloudFS Validation ' + uuid.uuid4().hex[:10]
        project = manager.CreateProject(name)
        assert project
        report['createdProjects'].append(name)
        assert project.SetSettings({'timelineResolutionWidth': '1920',
                                    'timelineResolutionHeight': '1080',
                                    'timelineFrameRate': '24'})
        pool = project.GetMediaPool()
        # Use the documented path-list overload for single MOV files; this
        # invokes Resolve's media importer for the mounted path directly.
        clips = pool.ImportMedia([str(source)])
        assert clips and len(clips) == 1, 'Mounted media import returned no clips'
        check('importMountedMedia', {'path': str(source), 'clipCount': len(clips)})
        timeline = pool.CreateEmptyTimeline('Three reordered cuts')
        assert timeline
        edits = pool.AppendToTimeline([
            {'mediaPoolItem': clips[0], 'startFrame': start, 'endFrame': start + 96}
            for start in (0, 192, 96)
        ])
        assert edits and len(edits) == 3
        assert timeline.GetEndFrame() - timeline.GetStartFrame() == 288
        assert manager.SaveProject()
        check('editThreeCutsAndSave', {'frames': 288, 'sourceOrder': [0, 192, 96]})
        export = root / (name.replace(' ', '-') + '.drp')
        assert manager.ExportProject(name, str(export), False)
        rpc('flush')
        assert export.is_file() and export.stat().st_size > 0
        check('exportProjectToMountedVolume', {'bytes': export.stat().st_size,
              'sha256': hashlib.sha256(export.read_bytes()).hexdigest()})
        assert manager.CloseProject(project)
        imported_name = name + ' Reimported'
        assert manager.ImportProject(str(export), imported_name)
        report['createdProjects'].append(imported_name)
        project = manager.LoadProject(imported_name)
        assert project and project.GetCurrentTimeline().GetEndFrame() - project.GetCurrentTimeline().GetStartFrame() == 288
        check('reopenExportedProject')
        codecs = project.GetRenderCodecs('mov')
        codec = next((v for k, v in codecs.items() if 'ProRes 422 LT' in k), None)
        assert codec, 'Expected ProRes 422 LT render codec'
        assert project.SetCurrentRenderFormatAndCodec('mov', codec)
        assert project.SetCurrentRenderMode(1)
        render_name = 'Resolve-' + name.rsplit(' ', 1)[-1]
        assert project.SetRenderSettings({'SelectAllFrames': True, 'TargetDir': str(root),
                 'CustomName': render_name, 'ExportVideo': True, 'ExportAudio': True,
                 'FormatWidth': 1920, 'FormatHeight': 1080, 'FrameRate': 24})
        job = project.AddRenderJob()
        assert job and project.StartRendering([job])
        deadline = time.monotonic() + 300
        while project.IsRenderingInProgress():
            assert time.monotonic() < deadline, 'Render exceeded five minutes'
            time.sleep(1)
        status = project.GetRenderJobStatus(job)
        assert status['JobStatus'] == 'Complete', status
        rpc('flush')
        rendered = root / (render_name + '.mov')
        assert rendered.is_file()
        probe = json.loads(subprocess.check_output(['/opt/homebrew/bin/ffprobe', '-v', 'error',
                '-show_streams', '-show_format', '-of', 'json', str(rendered)], text=True))
        video = next(s for s in probe['streams'] if s['codec_type'] == 'video')
        assert int(video['nb_frames']) == 288 and video['width'] == 1920 and video['height'] == 1080
        assert any(s['codec_type'] == 'audio' for s in probe['streams'])
        check('renderToCloudAndProbe', {'jobStatus': status, 'path': str(rendered),
               'bytes': rendered.stat().st_size, 'frames': 288,
               'sha256': hashlib.sha256(rendered.read_bytes()).hexdigest()})
        assert manager.SaveProject()
        rpc('flush')
        report['finalStatus'] = rpc('status')
        assert synchronized_status(report['finalStatus'], root.parent, args.filespace), 'Final connected mount and zero pending writes were not confirmed'
        check('finalMountedFilesSynchronized', True)
        report['result'] = 'PASS'
    except Exception as exc:
        report['result'] = 'FAIL'
        report['error'] = str(exc)
        raise
    finally:
        save()


if __name__ == '__main__':
    main()
