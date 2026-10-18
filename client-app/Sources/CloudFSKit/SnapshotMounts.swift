// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

public struct SnapshotMount: Sendable, Decodable, Equatable, Identifiable {
    public var id: String { mountId }
    public let mountId: String
    public let filespace: String
    public let snapshotId: String
    public let name: String
    public let mountPath: String?
    public let status: String
    public let readOnly: Bool
    public var isMounted: Bool { status == "mounted" && !(mountPath ?? "").isEmpty }
}
public extension EngineClient {
    func mountSnapshot(filespace: String, snapshotID: String, at path: String?, name: String?) async throws -> SnapshotMount { throw EngineError.unavailable("Snapshot mounting requires the CloudFS background service") }
    func unmountSnapshot(mountID: String, force: Bool) async throws -> SnapshotMount { throw EngineError.unavailable("Snapshot mounting requires the CloudFS background service") }
    func snapshotMounts(filespace: String?) async throws -> [SnapshotMount] { [] }
}
public extension DaemonEngineClient {
    func mountSnapshot(filespace: String, snapshotID: String, at path: String?, name: String?) async throws -> SnapshotMount {
        try await callResult("snapshot.mount", .params(["filespace": .string(filespace), "snapshotId": .string(snapshotID),
                                                       "at": path.map(JSONValue.string), "name": name.map(JSONValue.string)]), as: SnapshotMount.self)
    }
    func unmountSnapshot(mountID: String, force: Bool) async throws -> SnapshotMount {
        try await callResult("snapshot.unmount", .params(["mountId": .string(mountID), "force": .bool(force)]), as: SnapshotMount.self)
    }
    func snapshotMounts(filespace: String?) async throws -> [SnapshotMount] {
        try await callResult("snapshot.mounts", .params(["filespace": filespace.map(JSONValue.string)]), as: [SnapshotMount].self)
    }
}
