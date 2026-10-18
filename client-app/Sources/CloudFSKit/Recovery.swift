// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

/// A local write the engine has retained because it could not commit safely.
public struct RecoveryItem: Identifiable, Sendable, Codable, Equatable {
    public let id: String
    public let path: String?
    public let bytes: Int64
    public let reason: String
    public let kind: String
    public let canRetry: Bool
    public let canExport: Bool

    public init(id: String, path: String? = nil, bytes: Int64, reason: String,
                kind: String, canRetry: Bool, canExport: Bool = true) {
        self.id = id; self.path = path; self.bytes = bytes; self.reason = reason
        self.kind = kind; self.canRetry = canRetry; self.canExport = canExport
    }

    public var displayName: String {
        guard let path, !path.isEmpty else { return "Local file \(id.prefix(8))" }
        return (path as NSString).lastPathComponent
    }
    public var suggestedFileName: String {
        let name = displayName.replacingOccurrences(of: ":", with: "-")
        let ext = (name as NSString).pathExtension
        let base = (name as NSString).deletingPathExtension
        return ext.isEmpty ? "\(name) (recovered)" : "\(base) (recovered).\(ext)"
    }
    public var statusTitle: String {
        switch kind {
        case "conflict": return "Another version needs review"
        case "deleted": return "File removed from the filespace"
        default: return "Upload needs attention"
        }
    }
}

public struct RecoveryExportResult: Sendable, Decodable, Equatable {
    public let path: String
    public let bytes: Int64
    public let sha256: String?
}

public extension EngineClient {
    func recoveryItems(filespace: String) async throws -> [RecoveryItem] {
        throw EngineError.unavailable("Recovery requires an updated background engine.")
    }
    func retryRecovery(filespace: String, itemID: String) async throws {
        throw EngineError.unavailable("Recovery requires an updated background engine.")
    }
    func exportRecovery(filespace: String, itemID: String, destination: String) async throws -> RecoveryExportResult {
        throw EngineError.unavailable("Recovery requires an updated background engine.")
    }
    func completeRecovery(filespace: String, itemID: String, destination: String) async throws {
        throw EngineError.unavailable("Recovery requires an updated background engine.")
    }
}
