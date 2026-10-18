#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Opt-in deterministic real-socket transfer benchmark; no credentials or cloud data.

Tests six HTTP/1.1 connections versus the scheduler-sized pool, with 50ms
response delay, 32 outstanding requests, and 128 MiB verified per variant.
Also verifies the total deadline cancels a continuously trickling response.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import threading
import time

PAYLOAD = bytes(i % 251 for i in range(1 << 20))

class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *_):
        pass
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', str(len(PAYLOAD)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        try:
            if self.path == '/trickle':
                for _ in range(100):
                    self.wfile.write(b'x' * 1024)
                    self.wfile.flush()
                    time.sleep(.05)
            else:
                time.sleep(.05)
                self.wfile.write(PAYLOAD)
        except (BrokenPipeError, ConnectionResetError):
            pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Choose a new output file.')
    repo = Path(__file__).resolve().parents[1]
    server = Server(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        env = os.environ.copy()
        env['CLOUDFS_HTTP_BENCHMARK_URL'] = f'http://127.0.0.1:{server.server_port}'
        env['CLOUDFS_HTTP_BENCHMARK_OUTPUT'] = str(args.output.resolve())
        result = subprocess.run(['swift', 'test', '--package-path', str(repo/'cloudfsd'), '-c', 'release', '--filter', 'RealHTTPTransferBenchmarkTests'], env=env)
        if result.returncode:
            raise SystemExit(result.returncode)
        print(json.dumps(json.loads(args.output.read_text()), indent=2))
    finally:
        server.shutdown()
        server.server_close()
