// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSMount — the mount-adapter seam. (DESIGN.md §1)
//
// The engine is mount-agnostic: it speaks a POSIX-ish object API and a
// `MountBackend` adapter maps a concrete mount technology's VFS ops onto
// `EngineDataPath` calls. The production backend is `SMBLoopbackMountBackend`
// (module CloudFSSMB): an in-daemon SMB2 server fronted by the macOS built-in
// smbfs client over loopback. This module holds the protocol + a no-op stub for
// headless/CI contexts where no real mount can be performed.

import Foundation
import CloudFSCore

/// A mounted-volume adapter. One `MountBackend` per mounted filespace; it
/// forwards VFS ops to the engine's `EngineDataPath`.
public protocol MountBackend: Sendable {
    /// Human name of the backend (for status/diagnostics).
    var kind: String { get }
    /// Whether the real mount technology is available in this build/host.
    var isAvailable: Bool { get }
    /// Mount `filespace` at `mountPoint`, forwarding ops to `engine`.
    /// `displayName` is the human filespace name shown in the Finder sidebar; nil
    /// falls back to the filespace id.
    func mount(filespace: FilespaceID, displayName: String?, at mountPoint: String,
               engine: any EngineDataPath) async throws
    /// Recheck kernel ownership and clean up any stale listener after external
    /// eject. False means absent/replaced; nil is an unobservable test backend.
    /// A foreign volume must never be unmounted or claimed by this operation.
    func reconcile(filespace: FilespaceID, at mountPoint: String) async throws -> Bool?
    /// Exact owned kernel source to persist for safe crash recovery, if known.
    func recoverySource(filespace: FilespaceID) async throws -> String?
    /// Unmount the filespace.
    func unmount(filespace: FilespaceID, force: Bool) async throws
}

public extension MountBackend {
    func reconcile(filespace: FilespaceID, at mountPoint: String) async throws -> Bool? { nil }
    func recoverySource(filespace: FilespaceID) async throws -> String? { nil }
}

/// A no-op backend: reports unavailable and refuses to mount, so headless/CI
/// builds (which can't perform a real mount) stay green. The daemon uses the real
/// `SMBLoopbackMountBackend`; this is the default only when no backend is injected.
public struct StubMountBackend: MountBackend {
    public init() {}
    public var kind: String { "stub" }
    public var isAvailable: Bool { false }
    public func mount(filespace: FilespaceID, displayName: String?, at mountPoint: String,
                      engine: any EngineDataPath) async throws {
        throw EngineError(.notConnected, "no mount backend available; built with StubMountBackend")
    }
    public func unmount(filespace: FilespaceID, force: Bool) async throws {
        throw EngineError(.notConnected, "no mount backend available; nothing to unmount")
    }
}

/// The default backend when none is injected (headless/CI): the no-op stub. The
/// daemon wires the real `SMBLoopbackMountBackend` explicitly.
public func defaultMountBackend() -> any MountBackend {
    StubMountBackend()
}
