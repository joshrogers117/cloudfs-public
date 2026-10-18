// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

public struct SnapshotMountParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public var snapshotId: String
    public var at: String?
    public var name: String?
    public init(filespace: FilespaceID, snapshotId: String, at: String? = nil, name: String? = nil) {
        self.filespace = filespace; self.snapshotId = snapshotId; self.at = at; self.name = name
    }
}
public struct SnapshotUnmountParams: Sendable, Codable, Equatable {
    public var mountId: String
    public var force: Bool?
    public init(mountId: String, force: Bool? = nil) { self.mountId = mountId; self.force = force }
}
public struct SnapshotMountsParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID?
    public init(filespace: FilespaceID? = nil) { self.filespace = filespace }
}
public struct SnapshotMount: Sendable, Codable, Equatable {
    public enum Status: String, Sendable, Codable { case mounted, unmounted, unavailable }
    public var mountId: String
    public var filespace: FilespaceID
    public var snapshotId: String
    public var name: String
    public var mountPath: String?
    public var status: Status
    public var readOnly: Bool = true
    public init(mountId: String, filespace: FilespaceID, snapshotId: String, name: String,
                mountPath: String? = nil, status: Status) {
        self.mountId = mountId; self.filespace = filespace; self.snapshotId = snapshotId
        self.name = name; self.mountPath = mountPath; self.status = status
    }
    public var filespaceRecord: EngineFilespace {
        EngineFilespace(id: mountId, name: name, status: mountPath == nil ? .disconnected : .connected,
                        mountPath: mountPath, role: "read", paused: false,
                        sourceFilespace: filespace, snapshotId: snapshotId, readOnly: true)
    }
}
public extension Engine {
    func snapshotMount(_ p: SnapshotMountParams) async throws -> SnapshotMount { throw EngineError(.unimplemented, "Snapshot mounting is unavailable") }
    func snapshotUnmount(_ p: SnapshotUnmountParams) async throws -> SnapshotMount { throw EngineError(.unimplemented, "Snapshot mounting is unavailable") }
    func snapshotMounts(_ p: SnapshotMountsParams) async throws -> [SnapshotMount] { [] }
}
