// SPDX-License-Identifier: AGPL-3.0-or-later
// cloudfsd — config parsing + the daemon runtime (wave-2b, owner: CORE).

import Foundation
import CloudFSCore
import CloudFSCrypto
import CloudFSGateway
import CloudFSTransfer
import CloudFSMount
import CloudFSSMB
import CloudFSControlPlane

/// The fully-resolved run configuration (flags > env > defaults).
struct DaemonConfig: Sendable {
    var engine: EngineConfig
    var keyFilePath: String?
    /// CLI/process-environment key files are operator-required. The app's
    /// daemon.env key.hex path is an optional migration override.
    var keyFileRequired: Bool = false
    /// Optional filespace authority for `keyFilePath`; a key file is never global.
    var keyFileFilespace: FilespaceID? = nil
    /// Deployment authority paired with `keyFileFilespace`.
    var keyFileGateway: String? = nil
    /// Organization authority paired with gateway and filespace.
    var keyFileOrganization: String? = nil
    var autoConnectFilespace: FilespaceID?
    /// M8 — an ADDITIONAL control socket for the sandboxed Finder Sync extension.
    /// The appex can only reach inside the App Group container, so the app
    /// provisions this as `<group container>/finder.sock`; same JSON-RPC control
    /// plane, second listener. nil → not bound (headless / no Finder integration).
    var finderSocketPath: String? = nil
    /// DEV/SMOKE ONLY: a seed JSON that backs a `LocalDevGateway` (namespace +
    /// per-block presigned URLs) instead of the real `HttpGatewayClient`. When set,
    /// the daemon also uses AES-256-CTR (spike-compat) so the seeded ciphertext
    /// decrypts. See `LocalDevGateway.swift` + E2E-SMOKE.md. nil → production path.
    var devSeedPath: String?
    /// Optional mountpoint: when set (with `--filespace`), auto-mount the filespace
    /// there at start so the daemon serves a real volume headless.
    var mountAt: String?
    /// Block cipher: `gcm` (production, default) or `ctr` (spike-compat AES-256-CTR).
    /// Decoupled from `--dev-seed` so the REAL gateway can serve CTR-encrypted blocks
    /// (the smoke/interop path). `--dev-seed` still implies CTR.
    var cipherMode: CipherMode = .aes256gcm

    /// `~/Library/Application Support/cloudfs/` (macOS) — kept short so the socket
    /// path under it fits AF_UNIX `sun_path` (≤103 usable bytes).
    static var defaultSupportDir: String {
        let home = NSHomeDirectory()
        return "\(home)/Library/Application Support/cloudfs"
    }

    /// Boolean flags that take NO value (presence = true).
    static let booleanFlags: Set<String> = ["--once", "--allow-insecure-http"]

    /// M7 — the provisioning env FILE the app writes for the agent-launched daemon.
    /// The launch-agent plist is static inside the app bundle, so dynamic config
    /// (gateway URL, token location, socket) can't live there; the app writes
    /// KEY=VALUE lines here instead. LOWEST priority: flags > process env > this.
    /// Candidates in order: an explicit path (flag/env), then the support dir —
    /// the app↔daemon rendezvous (also headless/render-node provisioning).
    /// The App Group container is deliberately NOT a candidate: macOS 15+
    /// consent-gates group-container access — open(2) blocks indefinitely on the
    /// TCC check — which hung daemon startup before the socket ever bound
    /// (2026-06-10). Neither the unsandboxed app nor the daemon needs it.
    static func loadEnvFile(_ explicitPath: String? = nil) throws -> [String: String] {
        // An explicit configuration selects one environment. Never silently use
        // the user's regular deployment if that file is missing or unreadable.
        if let explicitPath {
            guard let text = try? String(contentsOfFile: explicitPath, encoding: .utf8) else {
                throw EngineError(.invalidParams, "cannot read explicit environment file: \(explicitPath)")
            }
            return parseEnvContents(text)
        }
        let candidates = [explicitPath,
                          defaultSupportDir + "/daemon.env"].compactMap { $0 }
        for path in candidates {
            guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            return parseEnvContents(text)
        }
        return [:]
    }

    private static func parseEnvContents(_ text: String) -> [String: String] {
        var out: [String: String] = [:]
        for line in text.split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            guard !t.isEmpty, !t.hasPrefix("#"), let eq = t.firstIndex(of: "=") else { continue }
            out[String(t[..<eq])] = String(t[t.index(after: eq)...])
        }
        return out
    }

    static func parse(_ args: [String], environment suppliedEnvironment: [String: String]? = nil) throws -> DaemonConfig {
        var flags: [String: String] = [:]
        var i = 0
        while i < args.count {
            let a = args[i]
            if a.hasPrefix("--"), Self.booleanFlags.contains(a) {
                flags[String(a.dropFirst(2))] = "true"
                i += 1
            } else if a.hasPrefix("--") {
                let key = String(a.dropFirst(2))
                guard i + 1 < args.count else {
                    throw EngineError(.invalidParams, "flag \(a) requires a value")
                }
                flags[key] = args[i + 1]
                i += 2
            } else {
                i += 1
            }
        }
        let env = suppliedEnvironment ?? ProcessInfo.processInfo.environment
        let fileEnv = try loadEnvFile(flags["env-file"] ?? env["CLOUDFS_ENV_FILE"])
        func pick(_ flag: String, _ envKey: String, _ fallback: String?) -> String? {
            flags[flag] ?? env[envKey] ?? fileEnv[envKey] ?? fallback
        }

        let support = defaultSupportDir
        let socket = pick("control-socket", "CLOUDFS_SOCKET", "\(support)/cloudfsd.sock")!
        let cacheDir = pick("cache-dir", "CLOUDFS_CACHE_DIR", "\(support)/cache")!
        let gateway = pick("gateway", "CLOUDFS_GATEWAY", "http://127.0.0.1:8787")!
        // ONBOARDING.md "Defaults (decided)": flat 25 GB (decimal) default, no smart
        // sizing. Shown once on the first-run checklist with an edit affordance.
        let sizeStr = pick("cache-size", "CLOUDFS_CACHE_SIZE", String(25_000_000_000))!  // 25 GB
        guard let size = Int(sizeStr), size >= 0 else {
            throw EngineError(.invalidParams, "cache-size must be a non-negative integer, got \(sizeStr)")
        }
        let tokenFile = pick("token-file", "CLOUDFS_TOKEN_FILE", nil)
        func concurrency(_ flag: String, _ key: String, _ fallback: Int) throws -> Int {
            let raw = pick(flag, key, String(fallback))!
            guard let value = Int(raw), (1...kMaxTransferConcurrency).contains(value) else {
                throw EngineError(.invalidParams, "\(flag) must be an integer between 1 and \(kMaxTransferConcurrency)")
            }
            return value
        }
        let uploadConcurrency = try concurrency("upload-concurrency", "CLOUDFS_UPLOAD_CONCURRENCY", kDefaultUploadConcurrency)
        let downloadConcurrency = try concurrency("download-concurrency", "CLOUDFS_DOWNLOAD_CONCURRENCY", kDefaultDownloadConcurrency)
        let budgetRaw = pick("read-ahead-budget-mib", "CLOUDFS_READ_AHEAD_BUDGET_MIB", String(kDefaultReadAheadBudgetMiB))!
        guard let readAheadBudget = Int(budgetRaw), (8...128).contains(readAheadBudget) else {
            throw EngineError(.invalidParams, "read-ahead-budget-mib must be an integer between 8 and 128")
        }
        func diskBytes(_ flag: String, _ key: String, _ fallback: Int) throws -> Int {
            guard let value = Int(pick(flag, key, String(fallback))!), value >= 0 else {
                throw EngineError(.invalidParams, "\(flag) must be a non-negative byte count")
            }
            return value
        }
        let pendingLimit = try diskBytes("pending-write-limit", "CLOUDFS_PENDING_WRITE_LIMIT", JournalDiskBudget.defaultLimitBytes)
        let pendingReserve = try diskBytes("pending-write-reserve", "CLOUDFS_PENDING_WRITE_RESERVE", JournalDiskBudget.defaultReserveBytes)
        let keyFile = pick("key-file", "CLOUDFS_KEY_FILE", nil)
        let optionalKeyFile = ["1", "true", "yes"].contains(
            (fileEnv["CLOUDFS_KEY_FILE_OPTIONAL"] ?? "").lowercased())
        let keyFileRequired = flags["key-file"] != nil || env["CLOUDFS_KEY_FILE"] != nil
            || (fileEnv["CLOUDFS_KEY_FILE"] != nil && !optionalKeyFile)
        let finderSocket = pick("finder-socket", "CLOUDFS_FINDER_SOCKET", nil)
        let filespace = pick("filespace", "CLOUDFS_FILESPACE", nil)
        // Infer the scope only for a single-filespace daemon. Multi-filespace
        // configurations must explicitly bind a local key file.
        let keyFileFilespace = pick("key-filespace", "CLOUDFS_KEY_FILE_FILESPACE", filespace)
        let keyFileGateway = pick("key-gateway", "CLOUDFS_KEY_FILE_GATEWAY", nil)
        let keyFileOrganization = pick("key-org", "CLOUDFS_KEY_FILE_ORG", nil)
        let devSeed = pick("dev-seed", "CLOUDFS_DEV_SEED", nil)
        let mountAt = pick("mount-at", "CLOUDFS_MOUNT_AT", nil)
        // `--dev-seed` forces CTR (its seeded objects are CTR); otherwise honor
        // `--cipher` (gcm default), so the REAL gateway can serve CTR-encrypted blocks.
        let cipherStr = pick("cipher", "CLOUDFS_CIPHER", devSeed != nil ? "ctr" : "gcm")!
        let cipherMode: CipherMode
        switch cipherStr.lowercased() {
        case "ctr", "aes256ctr", "aes-256-ctr": cipherMode = .aes256ctr
        case "gcm", "aes256gcm", "aes-256-gcm": cipherMode = .aes256gcm
        default: throw EngineError(.invalidParams, "--cipher must be 'gcm' or 'ctr', got \(cipherStr)")
        }

        try validateSocketPath(socket)
        if let finderSocket { try validateSocketPath(finderSocket) }

        // Audit B15 (TLS policy): refuse a plaintext `http://` gateway over a NON-loopback host
        // unless the operator explicitly opts in. The bearer token + presign mints ride this
        // channel; a cleartext non-local gateway exposes them to a network attacker. Loopback
        // http (dev) is allowed; any other http:// requires --allow-insecure-http.
        let allowInsecure = flags["allow-insecure-http"] != nil
            || ["1", "true", "yes"].contains((env["CLOUDFS_ALLOW_INSECURE_HTTP"]
                ?? fileEnv["CLOUDFS_ALLOW_INSECURE_HTTP"] ?? "").lowercased())
        try validateGatewayTLS(gateway, allowInsecure: allowInsecure)

        if keyFileRequired && (keyFile == nil || keyFileFilespace?.isEmpty != false
            || FilespaceKeyResolver.normalizedGateway(keyFileGateway) == nil
            || keyFileOrganization?.isEmpty != false) {
            throw EngineError(.invalidParams,
                "an explicitly configured CLOUDFS_KEY_FILE requires matching CLOUDFS_KEY_FILE_FILESPACE, CLOUDFS_KEY_FILE_GATEWAY, and CLOUDFS_KEY_FILE_ORG bindings")
        }

        let engine = EngineConfig(cacheDir: cacheDir, cacheSizeBytes: size,
                                  controlSocketPath: socket, gatewayBaseURL: gateway,
                                  tokenFilePath: tokenFile, uploadConcurrency: uploadConcurrency,
                                  downloadConcurrency: downloadConcurrency,
                                  readAheadBudgetMiB: readAheadBudget, pendingWriteLimitBytes: pendingLimit,
                                  pendingWriteReserveBytes: pendingReserve)
        return DaemonConfig(engine: engine, keyFilePath: keyFile,
                            keyFileRequired: keyFileRequired,
                            keyFileFilespace: keyFileFilespace,
                            keyFileGateway: keyFileGateway,
                            keyFileOrganization: keyFileOrganization,
                            autoConnectFilespace: filespace,
                            finderSocketPath: finderSocket, devSeedPath: devSeed,
                            mountAt: mountAt, cipherMode: cipherMode)
    }

    /// Audit B15 (TLS policy): reject a plaintext `http://` gateway over a NON-loopback host
    /// unless `allowInsecure`. The bearer token + presign mints ride this channel, so a
    /// cleartext non-local gateway leaks them to a network attacker. Loopback http (dev) is fine.
    static func validateGatewayTLS(_ url: String, allowInsecure: Bool) throws {
        guard let comps = URLComponents(string: url) else {
            throw EngineError(.invalidParams, "invalid gateway URL: \(url)")
        }
        let scheme = (comps.scheme ?? "").lowercased()
        if scheme == "https" { return }
        if scheme == "http" {
            let host = (comps.host ?? "").lowercased()
            let isLoopback = host == "localhost" || host == "127.0.0.1" || host == "::1" || host.hasSuffix(".localhost")
            if isLoopback || allowInsecure { return }
            throw EngineError(.invalidParams,
                "refusing a plaintext http:// gateway (\(url)) over a non-loopback host — it leaks the bearer token. Use https://, or pass --allow-insecure-http (or CLOUDFS_ALLOW_INSECURE_HTTP=1) to override.")
        }
        throw EngineError(.invalidParams, "gateway URL must be http:// or https://, got scheme '\(scheme)'")
    }

    /// AF_UNIX `sun_path` holds ≤104 bytes incl. the NUL terminator (≤103 usable).
    /// A longer path fails `bind(2)` with a confusing EINVAL, so reject early.
    static func validateSocketPath(_ path: String) throws {
        let bytes = path.utf8.count
        guard bytes <= 103 else {
            throw EngineError(.invalidParams,
                "control socket path is \(bytes) bytes; AF_UNIX sun_path allows at most 103 (use a shorter --control-socket)")
        }
    }
}

/// The daemon: owns the engine + the control plane, binds the socket, runs until a
/// signal, then unmounts + stops the socket. `actor` so start/shutdown serialize.
actor Daemon {
    private let config: DaemonConfig
    private let engine: CloudFSEngine
    private let control: UnixSocketControlPlane
    private let finderControl = UnixSocketControlPlane()
    private var finderServeTask: Task<Void, Never>?
    private var serveTask: Task<Void, Never>?
    private var stopped = false

    init(config: DaemonConfig) {
        self.config = config
        let keyLoad = Daemon.loadKey(config.keyFilePath)
        let key = keyLoad.key
        if config.keyFileRequired, key == nil {
            FileHandleText.err("\u{001B}[1;31mcloudfsd: FATAL — the explicitly configured local key file is missing or invalid; refusing to fetch or substitute another key\u{001B}[0m")
        }
        if key != nil && (config.keyFileFilespace == nil || config.keyFileGateway == nil || config.keyFileOrganization == nil) {
            FileHandleText.err("cloudfsd: WARNING — ignoring the configured local key file because it is missing its filespace, gateway, and organization binding")
        } else if key != nil,
                  FilespaceKeyResolver.normalizedGateway(config.keyFileGateway!) != FilespaceKeyResolver.normalizedGateway(config.engine.gatewayBaseURL) {
            FileHandleText.err("cloudfsd: WARNING — ignoring the configured local key file because it is bound to a different gateway")
        }
        // DEV/SMOKE: a seed file swaps the HTTP gateway for a LocalDevGateway and the
        // production GCM pipeline for spike-compat AES-256-CTR (so seeded ciphertext
        // round-trips). Every OTHER stage (mount→cache→transfer→blob HTTP) stays real.
        let gateway: any GatewayClient
        let cipher: CipherMode
        let liveTokens: LiveBearerTokenProvider?
        if let seed = config.devSeedPath {
            if let local = try? LocalDevGateway(seedPath: seed) {
                gateway = local
                liveTokens = nil
                FileHandleText.err("cloudfsd: DEV gateway active (seed \(seed)); cipher=AES-256-CTR")
            } else {
                FileHandleText.err("cloudfsd: dev-seed \(seed) failed to load; falling back to HTTP gateway")
                let tokens = LiveBearerTokenProvider(filespace: config.autoConnectFilespace,
                                                     filePath: config.engine.tokenFilePath)
                liveTokens = tokens
                gateway = HttpGatewayClient(config: GatewayClientConfig(
                    baseURL: config.engine.gatewayBaseURL) { tokens.current() }, changeNotifications: true, streamingManifests: true)
            }
            cipher = .aes256ctr
        } else {
            // Auth B-1 (spec §6.4 D1): a LIVE token provider, not a fixed string —
            // the app renews the daemon token by REWRITING token.txt (the backend
            // soft-expires the prior token ~10 min later), so the token must be
            // re-read per request; a daemon restart would unmount the volume.
            let tokens = LiveBearerTokenProvider(filespace: config.autoConnectFilespace,
                                                 filePath: config.engine.tokenFilePath)
            liveTokens = tokens
            gateway = HttpGatewayClient(config: GatewayClientConfig(
                baseURL: config.engine.gatewayBaseURL) { tokens.current() }, changeNotifications: true, streamingManifests: true)
            // Honor --cipher so the REAL gateway can serve CTR-encrypted blocks.
            cipher = config.cipherMode
            FileHandleText.err("cloudfsd: HTTP gateway \(config.engine.gatewayBaseURL); cipher=\(cipher == .aes256ctr ? "AES-256-CTR" : "AES-256-GCM")")
        }
        // CTR is READ-ONLY (its keystream is reused across files); writes will fail.
        // Warn loudly in red so an admin who picked `--cipher ctr` for interop is not
        // surprised when saves error out — production filespaces must use GCM.
        if cipher == .aes256ctr {
            FileHandleText.err("\u{001B}[1;31mcloudfsd: WARNING — AES-256-CTR is DECRYPT-ONLY (spike interop); the CTR keystream is reused across files. WRITES WILL FAIL. Use --cipher gcm for any real filespace.\u{001B}[0m")
        }
        // The production mount: our in-daemon SMB2 server + the macOS built-in
        // smbfs client, loopback. This is the sole backend (the NFSv3 and FUSE-T
        // backends were removed after the SMB cutover) — mounted volumes get the
        // filespace name in the Finder sidebar, live CHANGE_NOTIFY updates, native
        // xattrs/streams, and byte-range locks, all in-process on the engine seam.
        let mountBackend: any MountBackend = SMBLoopbackMountBackend()
        // ONBOARDING.md "Key model": the resolver adds a THIRD tier (gateway fetch) after the two
        // existing local sources — see `FilespaceKeyResolver` below for the full precedence +
        // fallback story. One resolver instance per daemon process, shared across every filespace
        // this daemon connects (each fetched key is remembered independently, keyed by filespace).
        let keyResolver = FilespaceKeyResolver()
        self.engine = CloudFSEngine(config: config.engine, gateway: gateway,
                                    mount: mountBackend,
                                    // Every production key path goes through the
                                    // filespace-aware provider. Passing `key` as
                                    // Engine's fallback would reintroduce a global
                                    // key when a filespace lookup fails.
                                    cipherMode: cipher, key: nil,
                                    keyProvider: { fs in
                                        // Explicit key file → per-filespace Keychain → gateway.
                                        await keyResolver.resolve(filespace: fs, localKey: key,
                                                                  localKeyFilespace: config.keyFileFilespace,
                                                                  localKeyGateway: config.keyFileGateway,
                                                                  localKeyOrganization: config.keyFileOrganization,
                                                                  localKeyFileInvalid: keyLoad.invalidPresent,
                                                                  gatewayURL: config.engine.gatewayBaseURL,
                                                                  organization: liveTokens.flatMap { keyNamespaceOrganization(from: $0.current()) }
                                                                      ?? (config.devSeedPath != nil ? "local-dev" : nil),
                                                                  requireBoundLocalKey: config.keyFileRequired,
                                                                  gateway: gateway)
                                    })
        self.control = UnixSocketControlPlane()
    }

    /// Audit B15 — load the service-account BEARER TOKEN. Precedence:
    ///   1. macOS Keychain (`com.cloudfs.bearer`, account = filespace id) — the production path; the
    ///      token never lives in a plaintext file (provisioned via MDM / `security`);
    ///   2. the `--token-file` (headless render nodes / CI) — a 0600 file (a group/other-readable
    ///      token file is REJECTED, since a leaked bearer token authenticates every gateway call).
    /// A configured token FILE with a bad mode is a LOUD error (the daemon runs anonymous, which the
    /// gateway then rejects — better than silently authenticating with a world-readable secret).
    /// Returns "" only when NEITHER source yields a token (anonymous/dev).
    /// Internal (not private) so `LiveBearerTokenProvider` reuses the SAME loader for its
    /// initial load — one resolution order (Keychain → mode-checked file → ""), one log style.
    static func loadToken(_ path: String?, filespace: String?) -> String {
        do {
            let loaded = try BearerTokenStore.load(filespace: filespace, filePath: path)
            if loaded.source == "keychain" {
                FileHandleText.err("cloudfsd: bearer token loaded from Keychain for filespace \(filespace ?? "?")")
            }
            return loaded.token
        } catch {
            FileHandleText.err("\u{001B}[1;31mcloudfsd: WARNING — could not load bearer token: \(error). The daemon will run UNAUTHENTICATED (the gateway will reject it). Fix the token file (chmod 600) or provision the Keychain item.\u{001B}[0m")
            return ""
        }
    }
    /// Load the optional daemon-wide key-file override for headless/single-filespace
    /// use. Existing files must pass the 0600 and key-format checks. The standard
    /// app configuration names an optional migration file that may not exist;
    /// without it, each filespace resolves its own key through the resolver below.
    static func loadKey(_ path: String?) -> (key: FilespaceKey?, invalidPresent: Bool) {
        // An explicitly provisioned local key is authoritative and must not wait
        // on a Keychain permission dialog in a headless process.
        if let path, FileManager.default.fileExists(atPath: path) {
            do { return (try FilespaceKey(hexKeyFile: path), false) }
            catch {
                FileHandleText.err("cloudfsd: could not load master key from \(path): \(error)")
                return (nil, true)
            }
        }
        // Per-filespace Keychain lookup belongs in FilespaceKeyResolver. A key
        // for --filespace must never become a daemon-wide key for another mount.
        return (nil, false)
    }

    /// Ensure the socket's parent dir exists and no stale socket remains.
    private func prepareSocketDir() throws {
        let url = URL(fileURLWithPath: config.engine.controlSocketPath)
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try? FileManager.default.removeItem(at: url)   // remove a stale socket
        try FileManager.default.createDirectory(
            at: URL(fileURLWithPath: config.engine.cacheDir),
            withIntermediateDirectories: true)
    }

    /// Bind the socket and start serving in a background task. Returns once the
    /// socket file is observable on disk (so callers — and a smoke test — know the
    /// listener is bound), or throws if binding does not complete promptly.
    private func bindAndServe() async throws {
        try prepareSocketDir()
        let socket = config.engine.controlSocketPath
        let engine = self.engine
        let control = self.control
        serveTask = Task.detached {
            do { try await control.serve(socketPath: socket, engine: engine) }
            catch { FileHandleText.err("cloudfsd: control plane stopped: \(error)") }
        }
        // Wait (bounded) for the listener to bind the socket path.
        for _ in 0..<200 {   // up to ~2s
            if FileManager.default.fileExists(atPath: socket) { return }
            try? await Task.sleep(nanoseconds: 10_000_000)   // 10 ms
        }
        throw EngineError(.internal, "control socket did not bind at \(socket)")
    }

    /// M8 — bind the Finder-extension socket (same control plane, second listener).
    /// BEST-EFFORT: Finder badges are non-critical, so a bind failure logs and the
    /// daemon keeps running; the main control socket is the one that must work.
    private func bindFinderSocket() async {
        guard let path = config.finderSocketPath else { return }
        try? FileManager.default.createDirectory(
            at: URL(fileURLWithPath: path).deletingLastPathComponent(),
            withIntermediateDirectories: true)
        try? FileManager.default.removeItem(atPath: path)   // stale socket
        let engine = self.engine
        let finderControl = self.finderControl
        finderServeTask = Task.detached {
            do { try await finderControl.serve(socketPath: path, engine: engine) }
            catch { FileHandleText.err("cloudfsd: finder control plane stopped: \(error)") }
        }
        for _ in 0..<200 {   // up to ~2s
            if FileManager.default.fileExists(atPath: path) {
                FileHandleText.out("cloudfsd: finder socket on \(path)")
                return
            }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        FileHandleText.err("cloudfsd: finder socket did not bind at \(path) (badges unavailable)")
    }

    /// Auto-connect the configured filespace (best-effort; logs and continues).
    /// If `--mount-at` is set, also mount it there, in a detached task so the
    /// daemon's run loop keeps serving the control socket while the volume is live.
    private func autoConnect() async {
        guard let fs = config.autoConnectFilespace else { return }
        do { _ = try await engine.connect(FilespaceConnectParams(filespace: fs)) }
        catch { FileHandleText.err("cloudfsd: auto-connect \(fs) failed: \(error)") }

        guard let at = config.mountAt else { return }
        let engine = self.engine
        Task.detached {
            do {
                let m = try await engine.mount(MountParams(filespace: fs, at: at, rootPoint: nil))
                FileHandleText.out("cloudfsd: mounted \(fs) at \(m.mountPath ?? at)")
            } catch {
                FileHandleText.err("cloudfsd: mount \(fs) at \(at) failed: \(error)")
            }
        }
    }

    /// Headless smoke: bind + auto-connect, but no run loop / signal handlers.
    func startOnce() async throws {
        try await bindAndServe()
        await bindFinderSocket()
        await engine.remountPersisted()   // P2: re-establish mounts a crash left wedged
        await autoConnect()
    }

    /// Full run: bind, install signal handlers, park until a signal, then shut down.
    func run() async {
        do { try await bindAndServe() }
        catch {
            FileHandleText.err("cloudfsd: failed to bind \(config.engine.controlSocketPath): \(error)")
            return
        }
        await bindFinderSocket()
        await engine.remountPersisted()   // P2: re-establish mounts a crash left wedged
        await autoConnect()
        FileHandleText.out("cloudfsd \(CloudFSEngine.engineVersion) serving on \(config.engine.controlSocketPath) (control-api \(ControlAPI.version))")
        FileHandleText.out("  cache: \(config.engine.cacheDir)  gateway: \(config.engine.gatewayBaseURL)")

        await SignalWaiter.waitForTermination()
        FileHandleText.out("cloudfsd: signal received, shutting down")
        await shutdown()
    }

    /// Graceful teardown: drain pending write-back, unmount every filespace, stop the
    /// socket, remove the file. Audit B2: SIGTERM previously force-unmounted WITHOUT
    /// flushing, dropping dirty bytes. We now drain (bounded) before unmount and
    /// loudly report anything still un-durable — and the journal holds those bytes so
    /// they replay on the next start, so nothing is lost even if the drain times out.
    func shutdown() async {
        guard !stopped else { return }
        stopped = true
        if let spaces = try? await engine.filespaceList() {
            // Drain write-back first (bounded), per filespace, before tearing down.
            for fs in spaces {
                do {
                    let st = try await engine.flush(FlushParams(filespace: fs.id, path: "", wait: true, timeoutMs: 30_000))
                    if !st.inSync {
                        FileHandleText.err("cloudfsd: shutdown — \(st.pendingUploads) upload(s)/\(st.pendingBytes)B still pending for \(fs.id); journaled, will replay on next start")
                    }
                } catch {
                    FileHandleText.err("cloudfsd: shutdown — write-back drain for \(fs.id) did not complete (\(error)); bytes are journaled and replay on next start")
                }
            }
            for fs in spaces where fs.mountPath != nil {
                _ = try? await engine.unmount(UnmountParams(filespace: fs.id, force: true))
            }
        }
        await control.stop()
        serveTask?.cancel()
        try? FileManager.default.removeItem(atPath: config.engine.controlSocketPath)
        await finderControl.stop()
        finderServeTask?.cancel()
        if let finderSocket = config.finderSocketPath {
            try? FileManager.default.removeItem(atPath: finderSocket)
        }
    }

    static let helpText = """
    cloudfsd \(CloudFSEngine.engineVersion) — cloud-fs local filesystem engine

    USAGE: cloudfsd [options]

    OPTIONS:
      --control-socket <path>   UDS to bind (mode 0600). env CLOUDFS_SOCKET
      --cache-dir <path>        Root cache directory.      env CLOUDFS_CACHE_DIR
      --pending-write-limit <bytes>   All journals ceiling. env CLOUDFS_PENDING_WRITE_LIMIT
      --pending-write-reserve <bytes> Keep disk space free. env CLOUDFS_PENDING_WRITE_RESERVE
      --cache-size <bytes>      Cache ceiling in bytes.     env CLOUDFS_CACHE_SIZE
      --gateway <url>           Gateway base URL.           env CLOUDFS_GATEWAY
      --token-file <path>       Service-account token file. env CLOUDFS_TOKEN_FILE
      --key-file <path>         32-byte hex master key.     env CLOUDFS_KEY_FILE
      --key-filespace <id>      Bind key-file to this filespace. env CLOUDFS_KEY_FILE_FILESPACE
      --key-gateway <url>       Bind key-file to this gateway. env CLOUDFS_KEY_FILE_GATEWAY
      --key-org <id>            Bind key-file to this organization. env CLOUDFS_KEY_FILE_ORG
      --finder-socket <path>    EXTRA control socket for the sandboxed Finder Sync
                                appex (App Group container). env CLOUDFS_FINDER_SOCKET
      --filespace <id>          Auto-connect at start.      env CLOUDFS_FILESPACE
      --mount-at <path>         Auto-mount filespace here.   env CLOUDFS_MOUNT_AT
      --cipher <gcm|ctr>        Block cipher (default gcm).  env CLOUDFS_CIPHER
      --upload-concurrency <n>  Parallel uploads, 1–\(kMaxTransferConcurrency) (default \(kDefaultUploadConcurrency)). env CLOUDFS_UPLOAD_CONCURRENCY
      --download-concurrency <n> Parallel downloads, 1–\(kMaxTransferConcurrency) (default \(kDefaultDownloadConcurrency)). env CLOUDFS_DOWNLOAD_CONCURRENCY
      --read-ahead-budget-mib <n> Engine-wide speculative read-ahead budget, 8–128 MiB (default \(kDefaultReadAheadBudgetMiB)). env CLOUDFS_READ_AHEAD_BUDGET_MIB
      --allow-insecure-http     Permit a non-loopback http:// gateway (leaks the token).
                                env CLOUDFS_ALLOW_INSECURE_HTTP
      --dev-seed <file>         DEV/SMOKE: local gateway seed JSON (AES-256-CTR).
                                env CLOUDFS_DEV_SEED
      --once                    Bind, report, exit 0 (headless smoke).
      --version                 Print version and exit.
      --help                    Print this help and exit.

    The control socket speaks newline-delimited JSON-RPC 2.0 (CONTROL-API.md).
    """
}

/// Auth B-1 (spec §6.4 D1) — a LIVE bearer-token source for the gateway client.
///
/// The Mac app renews the daemon's gateway token by atomically REWRITING token.txt
/// (the backend soft-expires the previous token ~10 minutes later). A token captured
/// once at startup therefore goes permanently stale after the first renewal — a 401
/// loop only a daemon restart (which unmounts the volume) would clear. This provider
/// re-runs the SAME loader the daemon uses at startup (`BearerTokenStore.load`:
/// Keychain → mode-checked `--token-file` → "") whenever the token file's mtime
/// changed OR the cached value is older than `maxAge` (30 s — also catches a
/// Keychain-side rotation, which has no mtime to observe). The gateway client calls
/// `current()` per request (`GatewayClientConfig.tokenProvider`), so a rewrite is
/// picked up on the very next request. Steady state is one `stat(2)` per request;
/// when nothing changes, behavior is identical to the old fixed token.
final class LiveBearerTokenProvider: @unchecked Sendable {
    private let filespace: String?
    private let filePath: String?
    private let maxAge: TimeInterval

    private let lock = NSLock()
    private var token: String
    private var loadedAt: Date
    private var mtime: Date?

    init(filespace: String?, filePath: String?, maxAge: TimeInterval = 30) {
        self.filespace = filespace
        self.filePath = filePath
        self.maxAge = maxAge
        // Eager first load = the daemon's existing startup behavior verbatim
        // (Keychain log line / loud anonymous warning).
        self.token = Daemon.loadToken(filePath, filespace: filespace)
        self.loadedAt = Date()
        self.mtime = Self.modificationDate(filePath)
    }

    /// The current bearer token. Cheap (at most one stat) — called per gateway request.
    func current() -> String {
        lock.lock(); defer { lock.unlock() }
        let now = Date()
        let m = Self.modificationDate(filePath)
        if now.timeIntervalSince(loadedAt) < maxAge, m == mtime { return token }
        do {
            let reloaded = try BearerTokenStore.load(filespace: filespace, filePath: filePath)
            if reloaded.token != token {
                FileHandleText.err("cloudfsd: bearer token refreshed (source=\(reloaded.source)) — renewal picked up without restart")
                token = reloaded.token
            }
        } catch {
            // Keep serving the last-good token (the prior token stays valid through the
            // soft-cutover window) and warn — e.g. token.txt went group/other-readable.
            FileHandleText.err("\u{001B}[1;31mcloudfsd: WARNING — bearer token re-read failed: \(error); keeping the previously loaded token\u{001B}[0m")
        }
        loadedAt = now
        mtime = m
        return token
    }

    private static func modificationDate(_ path: String?) -> Date? {
        guard let path else { return nil }
        let attrs = try? FileManager.default.attributesOfItem(atPath: path)
        return attrs?[.modificationDate] as? Date
    }
}

/// ONBOARDING.md "Key model" (build step 2) — per-filespace key resolution's THIRD tier: a
/// gateway fetch when neither local source (Keychain, `--key-file`) has the key. This is what
/// makes a fresh device's first mount of a filespace actually work — today (pre-this-change) a
/// daemon with no locally-provisioned key FATALs on every read/write forever, because there was
/// no distribution mechanism at all.
///
/// Precedence:
///   1. `localKey` only when its explicit binding matches both gateway and filespace.
///   2. macOS Keychain, namespaced by normalized gateway and filespace.
///   3. NEW: `GET /v1/filespaces/:fs/key` (backend/API.md §key) over the SAME authenticated
///      gateway client the data plane uses. The response is validated (`format == "plain-v1"`,
///      else a loud, named-format rejection — never guess at unknown key material) and, on
///      success, cached into the Keychain so every LATER resolution (this run and every future
///      daemon launch) finds it locally and never re-fetches.
///
/// A Keychain WRITE failure after a successful fetch is NOT fatal — this repo has known
/// data-protection-keychain flakiness in dev/headless contexts (macOS 15+ TCC quirks). The
/// fetched key is kept in an in-memory fallback map for the life of this process (a WARNING is
/// logged) so the mount still works this session; only a re-fetch (not a crash) is the cost of
/// the Keychain staying unwritable.
///
/// Returns nil — logging exactly why — only when EVERY source comes up empty: no Keychain item,
/// no `--key-file`, AND the gateway fetch itself failed (unreachable / unauthorized / server
/// error) or returned something this daemon can't use.
/// The token's org claim is used only to partition local key caches. The gateway
/// remains the authority for every request; if the claim cannot be read, the
/// resolver skips local cache reuse and asks the gateway each time.
private func keyNamespaceOrganization(from token: String) -> String? {
    let parts = token.split(separator: ".")
    guard parts.count == 3 else { return nil }
    var payload = String(parts[1]).replacingOccurrences(of: "-", with: "+")
                                   .replacingOccurrences(of: "_", with: "/")
    while payload.count % 4 != 0 { payload += "=" }
    guard let data = Data(base64Encoded: payload),
          let claims = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let organization = claims["org"] as? String,
          !organization.isEmpty else { return nil }
    return organization
}

final class FilespaceKeyResolver: @unchecked Sendable {
    private let lock = NSLock()
    private var fetchedFallback: [String: FilespaceKey] = [:]
    private let keychainReader: @Sendable (String) -> FilespaceKey?

    init(keychainReader: @escaping @Sendable (String) -> FilespaceKey? = { account in
        #if canImport(Security)
        return FilespaceKey.fromKeychain(account: account)
        #else
        return nil
        #endif
    }) {
        self.keychainReader = keychainReader
    }

    func resolve(filespace: FilespaceID, localKey: FilespaceKey?,
                 localKeyFilespace: FilespaceID? = nil,
                 localKeyGateway: String? = nil,
                 localKeyOrganization: String? = nil,
                 localKeyFileInvalid: Bool = false,
                 gatewayURL: String,
                 organization: String? = nil,
                 requireBoundLocalKey: Bool = false,
                 gateway: any GatewayClient) async -> FilespaceKey? {
        let account = Self.keychainAccount(gatewayURL: gatewayURL, organization: organization, filespace: filespace)
        let gatewayIdentity = Self.normalizedGateway(gatewayURL)
        let localBindingMatches: Bool
        if let localKeyFilespace, let localKeyGateway, let localKeyOrganization,
           let gatewayIdentity,
           localKeyFilespace == filespace,
           localKeyOrganization == organization,
           Self.normalizedGateway(localKeyGateway) == gatewayIdentity {
            localBindingMatches = true
        } else {
            localBindingMatches = false
        }
        if requireBoundLocalKey {
            let isRequiredTarget = localKeyFilespace == filespace
                && Self.normalizedGateway(localKeyGateway) == gatewayIdentity
                && localKeyOrganization == organization
            guard !isRequiredTarget || (localKey != nil && localBindingMatches) else {
                FileHandleText.err("\u{001B}[1;31mcloudfsd: FATAL — the explicitly required key file is unavailable or is not bound to filespace \(filespace), this gateway, and the authenticated organization; refusing Keychain or gateway substitution\u{001B}[0m")
                return nil
            }
            if isRequiredTarget { return localKey }
        }
        if localKeyFileInvalid && localBindingMatches {
            FileHandleText.err("\u{001B}[1;31mcloudfsd: FATAL — the bound local key file is present but invalid for filespace \(filespace); refusing Keychain or gateway substitution\u{001B}[0m")
            return nil
        }
        if let localKey, localBindingMatches {
            return localKey
        }
        if let account, let k = keychainReader(account) { return k }
        if let account, let cached = cachedFallback(account) { return cached }   // prior fetch; Keychain write had failed

        do {
            let envelope = try await gateway.fetchMasterKeyEnvelope(filespace: filespace)
            guard envelope.format == "plain-v1" else {
                FileHandleText.err("\u{001B}[1;31mcloudfsd: FATAL — the gateway offered filespace \(filespace)'s key in format '\(envelope.format)', which this daemon does not understand (only 'plain-v1' is supported). Refusing to guess at unrecognized key material — update cloudfsd, or provision the key locally (Keychain item com.cloudfs.masterkey, or --key-file).\u{001B}[0m")
                return nil
            }
            guard let materialB64 = envelope.material,
                  let raw = Data(base64Encoded: materialB64),
                  let key = try? FilespaceKey(masterKeyBytes: raw) else {
                FileHandleText.err("\u{001B}[1;31mcloudfsd: FATAL — the gateway's key envelope for filespace \(filespace) was malformed (missing or invalid 'material'). Reads/writes will fail.\u{001B}[0m")
                return nil
            }
            #if canImport(Security)
            if let account, key.storeInKeychain(account: account) {
                FileHandleText.err("cloudfsd: fetched filespace \(filespace)'s master key from the gateway and cached it in the Keychain")
            } else {
                FileHandleText.err("cloudfsd: WARNING — fetched filespace \(filespace)'s master key from the gateway but could not cache it in the Keychain; using it in-memory for this session only (expect a re-fetch on the next daemon start)")
                if let account { setCachedFallback(account, key) }
            }
            #else
            FileHandleText.err("cloudfsd: fetched filespace \(filespace)'s master key from the gateway (no Keychain on this platform; using it in-memory for this session only)")
            if let account { setCachedFallback(account, key) }
            #endif
            return key
        } catch {
            FileHandleText.err("\u{001B}[1;31mcloudfsd: FATAL — no matching local master key for filespace \(filespace) (deployment-scoped Keychain/key file) AND fetching it from the gateway failed: \(error). Reads/writes will fail until this is fixed — check connectivity/authorization, or provision the key locally (Keychain, a gateway-and-filespace-bound key file, or an admin running POST …/spaces/\(filespace)/key/import on the server).\u{001B}[0m")
            return nil
        }
    }

    /// Canonical deployment identity used for both local-file bindings and
    /// Keychain accounts. Ignore cosmetic case/default-port/trailing-slash
    /// differences, while keeping scheme, host, port and base path significant.
    static func normalizedGateway(_ raw: String?) -> String? {
        guard let raw, var parts = URLComponents(string: raw),
              let scheme = parts.scheme?.lowercased(),
              let host = parts.host?.lowercased(),
              parts.user == nil, parts.password == nil,
              parts.query == nil, parts.fragment == nil else { return nil }
        parts.scheme = scheme
        parts.host = host
        if (scheme == "http" && parts.port == 80) || (scheme == "https" && parts.port == 443) {
            parts.port = nil
        }
        var path = parts.percentEncodedPath
        while path.count > 1 && path.hasSuffix("/") { path.removeLast() }
        if path == "/" { path = "" }
        parts.percentEncodedPath = path
        return parts.string
    }

    static func keychainAccount(gatewayURL: String, organization: String?, filespace: FilespaceID) -> String? {
        guard let gateway = normalizedGateway(gatewayURL),
              let organization, !organization.isEmpty else { return nil }
        func encoded(_ value: String) -> String {
            Data(value.utf8).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        return "v2.\(encoded(gateway)).\(encoded(organization)).\(encoded(filespace))"
    }

    private func cachedFallback(_ account: String) -> FilespaceKey? {
        lock.lock(); defer { lock.unlock() }
        return fetchedFallback[account]
    }

    private func setCachedFallback(_ account: String, _ key: FilespaceKey) {
        lock.lock(); defer { lock.unlock() }
        fetchedFallback[account] = key
    }
}

/// Blocks until SIGINT or SIGTERM. Uses `DispatchSourceSignal` so the cooperative
/// pool is never blocked; the awaiting Task resumes once on the first signal.
enum SignalWaiter {
    static func waitForTermination() async {
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            let box = ResumeOnce(cont)
            for sig in [SIGINT, SIGTERM] {
                signal(sig, SIG_IGN)   // ignore default handler; the source observes it
                let src = DispatchSource.makeSignalSource(signal: sig, queue: .global())
                src.setEventHandler { box.fire() }
                src.resume()
                box.retain(src)
            }
        }
    }

    /// Resume the continuation exactly once, keeping the dispatch sources alive
    /// until then.
    private final class ResumeOnce: @unchecked Sendable {
        private let lock = NSLock()
        private var cont: CheckedContinuation<Void, Never>?
        private var sources: [DispatchSourceSignal] = []
        init(_ c: CheckedContinuation<Void, Never>) { cont = c }
        func retain(_ s: DispatchSourceSignal) { lock.lock(); sources.append(s); lock.unlock() }
        func fire() {
            lock.lock()
            let c = cont; cont = nil
            sources.forEach { $0.cancel() }; sources.removeAll()
            lock.unlock()
            c?.resume()
        }
    }
}
