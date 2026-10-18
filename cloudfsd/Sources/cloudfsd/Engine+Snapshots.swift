// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CryptoKit
import CloudFSCore
import CloudFSGateway
import CloudFSTransfer
import CloudFSMount

struct EngineSnapshotSession: Sendable {
    var record: SnapshotMount
    let roots: [FilespaceMountRoot]
    var dataPath: (any EngineDataPath)?
}
extension CloudFSEngine {
    public func snapshotMount(_ p: SnapshotMountParams) async throws -> SnapshotMount {
        guard !p.snapshotId.isEmpty, !p.filespace.hasPrefix("snapshot-") else { throw EngineError(.invalidParams, "Choose a source filespace and snapshot") }
        await beginMountOperation(p.filespace)
        defer { endMountOperation(p.filespace) }
        if (try? require(p.filespace)) == nil { _ = try await connectSession(FilespaceConnectParams(filespace: p.filespace)) }
        let source = try require(p.filespace)
        let mountID = "snapshot-" + SHA256.hash(data: Data((p.filespace + "\0" + p.snapshotId).utf8)).prefix(16).map { String(format: "%02x", $0) }.joined()
        let info = try await gateway.snapshotMountInfo(filespace: p.filespace, snapshotID: p.snapshotId)
        guard info.streamsCaptured != false else { throw EngineError(.conflict, "This older snapshot does not include Mac resource forks. Browse it in the app or create a new snapshot to mount a complete Finder volume.") }
        guard !info.roots.isEmpty else { throw EngineError(.permissionDenied, "No folders in this snapshot are available") }
        if let existing = snapshotSessions[mountID] {
            try await reconcileSnapshot(mountID)
            if let mounted = snapshotSessions[mountID]?.record, let current = mounted.mountPath {
                if let at = p.at, try KernelMountTable.canonicalMountPath(at) != current { throw EngineError(.conflict, "Eject the snapshot before moving its mount location") }
                return mounted
            }
            _ = existing
        }
        let gateway = SnapshotReadGateway(base: self.gateway, filespace: p.filespace, snapshotID: p.snapshotId)
        let transfer = RealTransferEngine(cache: source.cache, crypto: source.crypto, gateway: gateway, blob: blob, blockSize: blockSize)
        let base = try SnapshotDataPath(filespace: p.filespace, gateway: gateway, transfer: transfer, crypto: source.crypto,
                                       spillDir: URL(fileURLWithPath: config.cacheDir).appendingPathComponent("snapshot-spill/" + mountID).path, blob: blob)
        // A scoped snapshot and a single authorized shared root open directly.
        let direct = info.roots.count == 1 ? InodeID(info.roots[0].id) : nil
        let view = RootedDataPath(base: base, roots: info.roots, directRoot: direct)
        let name = p.name ?? info.snapshot.name ?? "Snapshot \(p.snapshotId)"
        let path = try KernelMountTable.canonicalMountPath(p.at ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("cloudfs/" + mountID).path)
        persistMountIntent(filespace: mountID, mountPoint: path, rootPoint: nil, name: name, sourceFilespace: p.filespace, snapshotId: p.snapshotId)
        do { try await mount.mount(filespace: mountID, displayName: name, at: path, engine: view) }
        catch { removeMountIntent(filespace: mountID); throw error }
        let record = SnapshotMount(mountId: mountID, filespace: p.filespace, snapshotId: p.snapshotId, name: name, mountPath: path, status: .mounted)
        snapshotSessions[mountID] = EngineSnapshotSession(record: record, roots: info.roots, dataPath: view)
        persistMountIntent(filespace: mountID, mountPoint: path, rootPoint: nil, name: name,
                           source: try? await mount.recoverySource(filespace: mountID), sourceFilespace: p.filespace, snapshotId: p.snapshotId)
        startSnapshotMonitor()
        return record
    }
    public func snapshotUnmount(_ p: SnapshotUnmountParams) async throws -> SnapshotMount {
        guard let existing = snapshotSessions[p.mountId] else { throw EngineError(.notFound, "Snapshot is not mounted") }
        await beginMountOperation(existing.record.filespace)
        defer { endMountOperation(existing.record.filespace) }
        return try await unmountSnapshot(p.mountId, force: p.force ?? false)
    }
    /// Caller holds the source filespace's mount lifecycle gate.
    private func unmountSnapshot(_ id: String, force: Bool, unavailable: Bool = false) async throws -> SnapshotMount {
        guard var session = snapshotSessions[id] else { throw EngineError(.notFound, "Snapshot is not mounted") }
        if session.record.mountPath != nil { try await mount.unmount(filespace: id, force: force) }
        session.record.mountPath = nil; session.record.status = unavailable ? .unavailable : .unmounted
        session.dataPath = nil
        snapshotSessions[id] = session
        removeMountIntent(filespace: id)
        return session.record
    }
    func unmountSnapshotsForParent(_ filespace: String, force: Bool) async throws {
        for id in snapshotSessions.values.filter({ $0.record.filespace == filespace }).map(\.record.mountId) {
            _ = try await unmountSnapshot(id, force: force)
            snapshotSessions[id] = nil
        }
    }
    private func reconcileSnapshot(_ id: String) async throws {
        guard var session = snapshotSessions[id], let path = session.record.mountPath else { return }
        if try await mount.reconcile(filespace: id, at: path) == false {
            session.record.mountPath = nil; session.record.status = .unmounted; session.dataPath = nil
            snapshotSessions[id] = session; removeMountIntent(filespace: id); return
        }
        do {
            let info = try await gateway.snapshotMountInfo(filespace: session.record.filespace, snapshotID: session.record.snapshotId)
            // Revoking any captured root detaches this immutable projection; remount
            // can construct the reduced view. It never silently changes the mount.
            let available = Set(info.roots.map(\.id))
            guard session.roots.allSatisfy({ available.contains($0.id) }) else { throw EngineError(.permissionDenied, "Snapshot access changed") }
        } catch let error as EngineError where error.kind == .permissionDenied || error.kind == .notFound {
            _ = try await unmountSnapshot(id, force: true, unavailable: true)
        }
    }
    public func snapshotMounts(_ p: SnapshotMountsParams) async throws -> [SnapshotMount] {
        let parents = Set(snapshotSessions.values.filter { p.filespace == nil || $0.record.filespace == p.filespace }.map(\.record.filespace))
        for parent in parents.sorted() {
            await beginMountOperation(parent)
            do {
                for id in snapshotSessions.values.filter({ $0.record.filespace == parent }).map(\.record.mountId) {
                    do { try await reconcileSnapshot(id) }
                    catch let error as EngineError where error.kind == .networkError || error.kind == .gatewayError {
                        // An offline permission check does not eject or invent a
                        // new kernel state. Individual reads continue to fail closed.
                        continue
                    }
                }
                endMountOperation(parent)
            } catch { endMountOperation(parent); throw error }
        }
        return snapshotSessions.values.map(\.record).filter { p.filespace == nil || $0.filespace == p.filespace }.sorted { $0.mountId < $1.mountId }
    }
    private func startSnapshotMonitor() {
        guard snapshotMonitor == nil else { return }
        snapshotMonitor = Task.detached(priority: .utility) { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(for: .seconds(5)) } catch { return }
                guard let self else { return }
                _ = try? await self.snapshotMounts(SnapshotMountsParams())
            }
        }
    }
}
