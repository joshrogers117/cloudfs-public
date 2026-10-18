// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore

extension CloudFSEngine {
    public func linkCreate(_ p: LinkCreateParams) async throws -> LinkCreateResult {
        let session = try require(p.filespace)
        let path = try normalizePinPath(p.path)
        let roots = try await pinMountRoots(p.filespace)
        guard !roots.isEmpty else { throw EngineError(.permissionDenied, "No shared folders are available") }
        if roots.count == 1 && roots[0].id == "root" {
            session.mountRoots = nil; session.directMountRoot = nil
        } else {
            session.mountRoots = roots
            session.directMountRoot = roots.count == 1 && roots[0].mountAsRoot ? InodeID(roots[0].id) : nil
        }
        let projected = try await resolveInode(p.filespace, path: path)
        if projected == .root, session.mountRoots != nil, session.directMountRoot == nil {
            throw EngineError(.invalidParams, "Use a filespace link for the shared volume root")
        }
        let actual = projected == .root ? (session.directMountRoot ?? projected) : projected
        // Recheck ACL and containment after resolving the namespace. A stale
        // mounted listing or a concurrent move cannot widen link access.
        _ = try await projectedPathForInode(p.filespace, id: actual)
        return LinkCreateResult(filespace: p.filespace, itemId: actual)
    }

    public func linkResolve(_ p: LinkResolveParams) async throws -> LinkResolveResult {
        _ = try require(p.filespace)
        let path = try await projectedPathForInode(p.filespace, id: p.itemId)
        return LinkResolveResult(filespace: p.filespace, path: path)
    }
}
