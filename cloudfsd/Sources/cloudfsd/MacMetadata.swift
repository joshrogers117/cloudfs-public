// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore
import CloudFSCrypto

/// The gateway transports a bounded encrypted AFP_AfpInfo envelope in a directory
/// page. Only its original inode/name key may turn it into SMB FinderInfo bytes.
func decryptMacMetadata(_ item: ItemMetadata, crypto: any BlockCrypto) async throws -> ItemMetadata {
    guard let encrypted = item.finderInfoCiphertext else { return item }
    guard encrypted.count <= 256 else { throw EngineError(.syncFailed, "Finder metadata envelope is too large") }
    var index: UInt64 = 0xcbf2_9ce4_8422_2325
    for byte in "AFP_AfpInfo".utf8 { index ^= UInt64(byte); index = index &* 0x0000_0100_0000_01B3 }
    let data = try await crypto.decryptBlock(encrypted, itemID: item.id, blockIndex: Int(index & 0x7FFF_FFFF))
    guard data.count == 60 else { throw EngineError(.syncFailed, "Finder metadata has an invalid length") }
    return ItemMetadata(id: item.id, parent: item.parent, name: item.name, isDir: item.isDir,
                        size: item.size, contentVersion: item.contentVersion, metadataVersion: item.metadataVersion,
                        createdAt: item.createdAt, modifiedAt: item.modifiedAt, accessedAt: item.accessedAt, changedAt: item.changedAt, fileAttributes: item.fileAttributes,
                        rsrcForkSize: item.rsrcForkSize, finderInfo: data.subdata(in: 16..<48))
}
