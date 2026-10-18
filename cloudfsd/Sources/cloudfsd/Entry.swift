// SPDX-License-Identifier: AGPL-3.0-or-later
// cloudfsd — executable entry point (wave-2b, owner: CORE).
//
// Parses the run line (DESIGN.md §2.3) from flags + env, builds the concrete
// `CloudFSEngine`, starts the real `UnixSocketControlPlane` on the UDS, and runs
// until SIGINT/SIGTERM — then unmounts every filespace and stops the socket
// cleanly. `--version` / `--help` / `--once` give a headless smoke path.
//
// Run line (flags override env override defaults):
//   --control-socket <path>   CLOUDFS_SOCKET     UDS to bind (mode 0600).
//   --cache-dir <path>        CLOUDFS_CACHE_DIR  root cache directory.
//   --cache-size <bytes>      CLOUDFS_CACHE_SIZE cache ceiling, bytes.
//   --gateway <url>           CLOUDFS_GATEWAY    gateway base URL.
//   --token-file <path>       CLOUDFS_TOKEN_FILE service-account bearer token file.
//   --key-file <path>         CLOUDFS_KEY_FILE   32-byte hex filespace master key.
//   --filespace <id>          CLOUDFS_FILESPACE  auto-connect this filespace at start.
//   --version | --help | --once
//
// AF_UNIX `sun_path` is ≤104 bytes incl. NUL (≤103 usable): the default socket
// lives under `~/Library/Application Support/cloudfs/` and is length-validated.

import Foundation
import CloudFSCore
import CloudFSCrypto
import CloudFSGateway
import CloudFSMount
import CloudFSControlPlane

@main
struct CloudFSD {
    static func main() async {
        let args = Array(CommandLine.arguments.dropFirst())

        if args.contains("--help") || args.contains("-h") {
            FileHandleText.out(Daemon.helpText)
            exit(0)
        }
        if args.contains("--version") || args.contains("-v") {
            FileHandleText.out("cloudfsd \(CloudFSEngine.engineVersion) (control-api \(ControlAPI.version))")
            exit(0)
        }

        let config: DaemonConfig
        do {
            config = try DaemonConfig.parse(args)
        } catch let e as EngineError {
            FileHandleText.err("cloudfsd: \(e.message)")
            exit(Int32(e.exitCode))
        } catch {
            FileHandleText.err("cloudfsd: \(error)")
            exit(2)
        }

        let daemon = Daemon(config: config)

        if args.contains("--once") {
            // Headless smoke: bind, report, shut down — no run loop, no signals.
            do {
                try await daemon.startOnce()
                FileHandleText.out("cloudfsd \(CloudFSEngine.engineVersion): bound \(config.engine.controlSocketPath), serving OK; --once exiting 0")
                await daemon.shutdown()
                exit(0)
            } catch let e as EngineError {
                FileHandleText.err("cloudfsd: \(e.message)")
                await daemon.shutdown()
                exit(Int32(e.exitCode))
            } catch {
                FileHandleText.err("cloudfsd: \(error)")
                await daemon.shutdown()
                exit(1)
            }
        }

        // Normal run: serve until a signal, then graceful shutdown.
        await daemon.run()
        exit(0)
    }
}

/// Tiny stdout/stderr helpers (avoid print() buffering quirks under capture).
enum FileHandleText {
    static func out(_ s: String) { FileHandle.standardOutput.write(Data((s + "\n").utf8)) }
    static func err(_ s: String) { FileHandle.standardError.write(Data((s + "\n").utf8)) }
}
