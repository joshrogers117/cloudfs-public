// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

/// SMB byte ranges are UInt64. Decimal strings keep JSON intermediaries exact.
public struct FileLockRange: Sendable, Equatable, Codable {
    public let offset: UInt64
    public let length: UInt64
    public let exclusive: Bool
    public init(offset: UInt64, length: UInt64, exclusive: Bool) {
        self.offset = offset; self.length = length; self.exclusive = exclusive
    }
    private enum CodingKeys: String, CodingKey { case offset, length, exclusive }
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        guard let offset = UInt64(try c.decode(String.self, forKey: .offset)),
              let length = UInt64(try c.decode(String.self, forKey: .length)),
              !offset.addingReportingOverflow(length).overflow else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Invalid byte range"))
        }
        self.offset = offset; self.length = length; self.exclusive = try c.decode(Bool.self, forKey: .exclusive)
    }
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(String(offset), forKey: .offset); try c.encode(String(length), forKey: .length)
        try c.encode(exclusive, forKey: .exclusive)
    }
}
