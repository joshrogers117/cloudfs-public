// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB — the PRODUCTION mount backend: our in-daemon SMB2 server + the
// macOS built-in smbfs client, loopback. Replaces the NFS backend (hard cutover).
//
// Auth: a synthetic random NTLMv2 credential is minted per mount. We try to stash
// it in the login keychain so `mount_smbfs -N` reads it without the password ever
// hitting argv; if that fails we fall back to an inline URL password (the
// credential is a random throwaway scoped to a loopback port, so this is safe,
// just less tidy). Persisting the credential across daemon restarts for
// transparent reconnect is a P6 item.
//
// nsmb.conf: we ensure a `[127.0.0.1]`-scoped section in the user preferences
// file (no root needed) so the client enables AAPL, dir caching, notify, and
// named streams for our loopback host only.

import Foundation
import CloudFSCore
import CloudFSMount

public final class SMBLoopbackMountBackend: MountBackend, @unchecked Sendable {

    private struct Session {
        let server: SMBServer
        let mountPoint: String
        let user: String
        let usedKeychain: Bool
        let port: UInt16
        let share: String
    }
    private let lock = NSLock()
    private var sessions: [FilespaceID: Session] = [:]

    public init() {}

    public var kind: String { "smb-loopback" }
    public var isAvailable: Bool { true }

    public func mount(filespace: FilespaceID, displayName: String?, at mountPoint: String,
                      engine: any EngineDataPath) async throws {
        // macOS records the resolved path in its mount table; unmounting a /tmp
        // alias can report success without detaching /private/tmp's actual volume.
        let mountPoint = try KernelMountTable.canonicalMountPath(mountPoint)
        if let previous = getSession(filespace) {
            if try ownsKernelMount(previous) { return }
            discardSession(filespace, previous)
        }
        guard try !KernelMountTable.snapshot().contains(where: { $0.path == mountPoint }) else {
            throw EngineError(.conflict, "Another volume is already mounted at the requested location")
        }
        if FileManager.default.fileExists(atPath: mountPoint) {
            let contents = try FileManager.default.contentsOfDirectory(atPath: mountPoint).filter { $0 != ".DS_Store" }
            guard contents.isEmpty else { throw EngineError(.conflict, "The local mount folder contains files. Move them before connecting the filespace.") }
        }
        let share = SMBShareName.sanitize(displayName ?? filespace)
        let cred = SyntheticCredential.generate()

        // 1. Our SMB server for this filespace on an ephemeral loopback port.
        let server = SMBServer(engine: engine, shareName: share,
                               credential: (user: cred.user, password: cred.password))
        let port = try server.start()

        // 2. Client tuning: ensure the [127.0.0.1] nsmb.conf section.
        NSMBConf.ensureLoopbackSection()

        // 3. Mount point + credential handoff.
        try FileManager.default.createDirectory(atPath: mountPoint, withIntermediateDirectories: true)
        let usedKeychain = Keychain.addSMBPassword(user: cred.user, password: cred.password, port: port)

        // 4. mount_smbfs. The SMB URL supports host:port.
        let urlAuth: String
        if usedKeychain {
            urlAuth = "\(cred.user)@127.0.0.1:\(port)"
        } else {
            urlAuth = "\(cred.user):\(cred.password)@127.0.0.1:\(port)"
        }
        let spec = "//\(urlAuth)/\(SMBShareName.urlComponent(share))"
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/sbin/mount_smbfs")
        proc.arguments = engine.isReadOnly ? ["-N", "-o", "ro", spec, mountPoint] : ["-N", spec, mountPoint]
        let errPipe = Pipe()
        proc.standardError = errPipe
        do { try proc.run() } catch {
            server.stop(); if usedKeychain { Keychain.deleteSMBPassword(user: cred.user) }
            throw EngineError(.internal, "mount_smbfs launch failed: \(error)")
        }
        proc.waitUntilExit()
        guard proc.terminationStatus == 0 else {
            let err = String(decoding: errPipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            server.stop(); if usedKeychain { Keychain.deleteSMBPassword(user: cred.user) }
            throw EngineError(.internal, "mount_smbfs exited \(proc.terminationStatus): \(err.trimmingCharacters(in: .whitespacesAndNewlines))")
        }

        // 5. Best-effort: stop Spotlight indexing the streaming volume.
        disableSpotlight(at: mountPoint)

        let session = Session(server: server, mountPoint: mountPoint,
                              user: cred.user, usedKeychain: usedKeychain, port: port, share: share)
        do {
            guard try ownsKernelMount(session) else {
                throw EngineError(.internal, "The kernel did not confirm the new CloudFS volume")
            }
            register(filespace, session)
        } catch {
            // A symlinked target or other path disagreement must not strand our
            // newly created volume after its server stops. Only our unique
            // disposable identity can authorize this cleanup, never its path alone.
            for entry in (try? KernelMountTable.snapshot()) ?? [] where
                entry.matchesSMB(path: entry.path, user: cred.user, port: port, share: share) {
                let cleanup = Process()
                cleanup.executableURL = URL(fileURLWithPath: "/sbin/umount")
                cleanup.arguments = ["-f", entry.path]
                if (try? cleanup.run()) != nil { cleanup.waitUntilExit() }
            }
            server.stop()
            if usedKeychain { Keychain.deleteSMBPassword(user: cred.user) }
            throw error
        }
    }

    private func register(_ filespace: FilespaceID, _ session: Session) {
        lock.lock(); sessions[filespace] = session; lock.unlock()
    }
    private func getSession(_ filespace: FilespaceID) -> Session? {
        lock.lock(); defer { lock.unlock() }
        return sessions[filespace]
    }

    private func ownsKernelMount(_ session: Session) throws -> Bool {
        try KernelMountTable.snapshot().contains {
            $0.matchesSMB(path: session.mountPoint, user: session.user, port: session.port, share: session.share)
        }
    }

    private func discardSession(_ filespace: FilespaceID, _ session: Session) {
        lock.withLock {
            if sessions[filespace]?.server === session.server { sessions[filespace] = nil }
        }
        session.server.stop()
        if session.usedKeychain { Keychain.deleteSMBPassword(user: session.user) }
    }

    public func recoverySource(filespace: FilespaceID) async throws -> String? {
        guard let session = getSession(filespace) else { return nil }
        return try KernelMountTable.snapshot().first {
            $0.matchesSMB(path: session.mountPoint, user: session.user, port: session.port, share: session.share)
        }?.source
    }

    public func reconcile(filespace: FilespaceID, at mountPoint: String) async throws -> Bool? {
        guard let session = getSession(filespace) else { return false }
        // The stored canonical path and source identify this exact session.
        // Do not stat/resolve the live mount path: a wedged volume can block it.
        if try ownsKernelMount(session) { return true }
        // The kernel volume was ejected (or a different volume replaced it).
        // Release only our listener and disposable credential, never umount it.
        discardSession(filespace, session)
        return false
    }

    public func unmount(filespace: FilespaceID, force: Bool) async throws {
        guard let session = getSession(filespace) else { return }
        guard try ownsKernelMount(session) else { discardSession(filespace, session); return }
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/sbin/umount")
        proc.arguments = force ? ["-f", session.mountPoint] : [session.mountPoint]
        do { try proc.run() }
        catch { throw EngineError(.internal, "umount launch failed: \(error)") }
        proc.waitUntilExit()
        guard try !ownsKernelMount(session) else {
            // Keep this exact volume's listener alive when busy unmount fails.
            throw EngineError(.internal, "The filespace is still mounted. Close files using it and try disconnecting again.")
        }
        discardSession(filespace, session)
    }

    private func disableSpotlight(at mountPoint: String) {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/mdutil")
        proc.arguments = ["-i", "off", mountPoint]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        // Spotlight can stall while inspecting another disconnected volume.
        // Its optional tuning must never block a successfully established mount.
        do { try proc.run() } catch { return }
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) {
            if proc.isRunning { proc.terminate() }
        }
    }
}

// MARK: - Synthetic credential

enum SyntheticCredential {
    /// URL-safe random user + password (no special chars, so inline URL auth is
    /// safe and no escaping is needed).
    static func generate() -> (user: String, password: String) {
        ("cfs-" + randomToken(8), randomToken(24))
    }
    private static func randomToken(_ n: Int) -> String {
        let alphabet = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        return String((0..<n).map { _ in alphabet[Int.random(in: 0..<alphabet.count)] })
    }
}

// MARK: - Share name sanitation

enum SMBShareName {
    static func urlComponent(_ name: String) -> String {
        name.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(CharacterSet(charactersIn: "-._~")))!
    }

    /// Strip characters illegal in an SMB share name / that would confuse the
    /// mount URL, cap length. The share name is what Finder shows as the volume.
    static func sanitize(_ raw: String) -> String {
        let illegal = Set("/\\[]:|<>+=;,?*\"@")
        var out = raw.unicodeScalars.filter { !illegal.contains(Character($0)) && $0.value >= 0x20 }
                                     .map(Character.init)
        if out.isEmpty { out = Array("cloudfs") }
        return String(out.prefix(80))
    }
}

// MARK: - nsmb.conf (user preferences scope, no root)

enum NSMBConf {
    static let path = (NSHomeDirectory() as NSString)
        .appendingPathComponent("Library/Preferences/nsmb.conf")

    /// Ensure a `[127.0.0.1]` section exists with our loopback tuning. Idempotent:
    /// if a section for that host is already present we leave the file untouched
    /// (we never rewrite the user's [default] or other host sections).
    static func ensureLoopbackSection() {
        let section = """
        [127.0.0.1]
        aapl_off=no
        dir_cache_off=no
        file_ids_off=no
        max_cached_per_dir=50000
        minauth=ntlmv2
        notify_off=no
        protocol_vers_map=2
        signing_required=no
        streams=yes
        """
        let existing = (try? String(contentsOfFile: path, encoding: .utf8)) ?? ""
        if existing.contains("[127.0.0.1]") { return }
        let combined = existing.isEmpty ? section + "\n"
                                        : existing + (existing.hasSuffix("\n") ? "" : "\n") + "\n" + section + "\n"
        try? combined.write(toFile: path, atomically: true, encoding: .utf8)
    }
}

// MARK: - Keychain (via the `security` CLI; best-effort)

enum Keychain {
    /// Add an internet-password item for the loopback SMB mount. Returns true on
    /// success. Trusts mount_smbfs so `-N` can read it non-interactively.
    @discardableResult
    static func addSMBPassword(user: String, password: String, port: UInt16) -> Bool {
        // Opt-in until verified live; inline-URL auth is the default reliable path.
        guard ProcessInfo.processInfo.environment["CLOUDFS_SMB_KEYCHAIN"] == "1" else { return false }
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        proc.arguments = ["add-internet-password", "-a", user, "-s", "127.0.0.1",
                          "-r", "smb ", "-P", String(port), "-w", password, "-U",
                          "-T", "/sbin/mount_smbfs"]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        do { try proc.run() } catch { return false }
        proc.waitUntilExit()
        return proc.terminationStatus == 0
    }

    static func deleteSMBPassword(user: String) {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        proc.arguments = ["delete-internet-password", "-a", user, "-s", "127.0.0.1"]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try? proc.run()
        proc.waitUntilExit()
    }
}
