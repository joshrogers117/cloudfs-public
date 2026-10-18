// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

public struct LinkCreateParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public var path: String
    public init(filespace: FilespaceID, path: String) { self.filespace = filespace; self.path = path }
}
public struct LinkCreateResult: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public var itemId: InodeID
    public init(filespace: FilespaceID, itemId: InodeID) { self.filespace = filespace; self.itemId = itemId }
}
public typealias LinkResolveParams = LinkCreateResult
public typealias LinkResolveResult = LinkCreateParams

public extension Engine {
    func linkCreate(_ p: LinkCreateParams) async throws -> LinkCreateResult { throw EngineError.unimplemented() }
    func linkResolve(_ p: LinkResolveParams) async throws -> LinkResolveResult { throw EngineError.unimplemented() }
}
