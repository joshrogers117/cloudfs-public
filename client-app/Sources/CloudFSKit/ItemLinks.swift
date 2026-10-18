// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

public struct EngineItemLink: Sendable, Decodable, Equatable {
    public let filespace: String
    public let itemId: String
}

public struct EngineLinkTarget: Sendable, Decodable, Equatable {
    public let filespace: String
    public let path: String
}

public extension EngineClient {
    func createItemLink(filespace: String, path: String) async throws -> EngineItemLink {
        throw EngineError.unavailable("Team links require an updated CloudFS background service.")
    }
    func resolveItemLink(filespace: String, itemID: String) async throws -> EngineLinkTarget {
        throw EngineError.unavailable("Team links require an updated CloudFS background service.")
    }
}
