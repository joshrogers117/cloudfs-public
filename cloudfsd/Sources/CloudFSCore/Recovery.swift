// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

/// A retained local write that needs user attention. No recovery operation
/// discards the journal or changes its optimistic concurrency base.
public struct RecoveryItem: Sendable, Codable, Equatable {
    public var id: String
    public var path: String?
    public var bytes: Int
    public var reason: String
    public var kind: String
    public var canRetry: Bool
    public var canExport: Bool
    public init(id: String, path: String? = nil, bytes: Int, reason: String,
                kind: String, canRetry: Bool, canExport: Bool = true) {
        self.id = id; self.path = path; self.bytes = bytes; self.reason = reason
        self.kind = kind; self.canRetry = canRetry; self.canExport = canExport
    }
}

public struct RecoveryItemParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public var itemId: InodeID
    public init(filespace: FilespaceID, itemId: InodeID) {
        self.filespace = filespace; self.itemId = itemId
    }
}

public struct RecoveryExportParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public var itemId: InodeID
    public var destination: String
    public init(filespace: FilespaceID, itemId: InodeID, destination: String) {
        self.filespace = filespace; self.itemId = itemId; self.destination = destination
    }
}

public struct RecoveryExportResult: Sendable, Codable, Equatable {
    public var path: String
    public var bytes: Int
    public var sha256: String?
    public init(path: String, bytes: Int, sha256: String? = nil) {
        self.path = path; self.bytes = bytes; self.sha256 = sha256
    }
}

public extension Engine {
    func recoveryList(_ p: FilespaceOnlyParams) async throws -> [RecoveryItem] { throw EngineError.unimplemented() }
    func recoveryRetry(_ p: RecoveryItemParams) async throws { throw EngineError.unimplemented() }
    func recoveryExport(_ p: RecoveryExportParams) async throws -> RecoveryExportResult { throw EngineError.unimplemented() }
    func recoveryComplete(_ p: RecoveryExportParams) async throws { throw EngineError.unimplemented() }
}
