// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore

extension CloudFSEngine {
    public func recoveryList(_ p: FilespaceOnlyParams) async throws -> [RecoveryItem] {
        let transfer = try sessionFor(p.filespace).transfer
        var items = try await transfer.recoveryItems(filespace: p.filespace)
        // The journal keys are opaque IDs. Names are best-effort: a deleted file
        // or revoked permission must not hide the retained local write.
        for index in items.indices where items[index].path == nil {
            if let metadata = try? await gateway.getItem(filespace: p.filespace, id: InodeID(items[index].id)) {
                items[index].path = metadata.name
            }
        }
        return items
    }

    public func recoveryRetry(_ p: RecoveryItemParams) async throws {
        let transfer = try sessionFor(p.filespace).transfer
        guard let item = try await transfer.recoveryItems(filespace: p.filespace)
            .first(where: { $0.id == p.itemId.rawValue }), item.canRetry else {
            throw EngineError(.conflict, "This local write cannot be retried safely. Save a local copy instead.")
        }
        try await gateway.authorizeWrite(filespace: p.filespace, id: p.itemId)
        try await resetWriteLease(filespace: p.filespace, itemID: p.itemId)
        try await transfer.retryRecovery(filespace: p.filespace, itemID: p.itemId)
    }

    public func recoveryExport(_ p: RecoveryExportParams) async throws -> RecoveryExportResult {
        // Export is a local salvage operation: revocation/deletion must not
        // strand bytes this Mac already acknowledged. The transfer layer rejects
        // overwrites, validates staged blocks and syncs the resulting new file.
        let destination = URL(fileURLWithPath: p.destination).standardizedFileURL.resolvingSymlinksInPath().path
        for filespace in try await filespaceList() {
            guard let mountPath = filespace.mountPath, !mountPath.isEmpty else { continue }
            let root = URL(fileURLWithPath: mountPath).standardizedFileURL.resolvingSymlinksInPath().path
            guard destination != root, !destination.hasPrefix(root + "/") else {
                throw EngineError(.invalidParams, "Save the recovery copy outside your CloudFS filespaces, such as in Documents or on a local drive.")
            }
        }
        return try await sessionFor(p.filespace).transfer.exportRecovery(
            filespace: p.filespace, itemID: p.itemId, destination: p.destination)
    }

    public func recoveryComplete(_ p: RecoveryExportParams) async throws {
        let transfer = try sessionFor(p.filespace).transfer
        try await withClosedWriteHandles(filespace: p.filespace, itemID: p.itemId) {
            try await transfer.completeRecovery(filespace: p.filespace, itemID: p.itemId, destination: p.destination)
        }
        noteRecoveryCompleted(filespace: p.filespace, itemID: p.itemId)
    }
}
