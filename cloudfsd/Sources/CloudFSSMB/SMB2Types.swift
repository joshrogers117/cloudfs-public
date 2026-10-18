// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB — SMB2 protocol constants and the packet header ([MS-SMB2]).
//
// Scope note: the loopback server negotiates dialect 2.1 (SMB 2.1) so that
// multi-credit large-MTU I/O (1 MiB reads) is on-spec via CAP_LARGE_MTU, without
// pulling in the SMB3 machinery (encryption negotiation, leasing, multichannel,
// validate-negotiate). Constants below are only those the mac smbfs client and
// our handlers actually touch.

import Foundation

// MARK: - Command ([MS-SMB2] §2.2.1.2)

public enum SMB2Command: UInt16, Sendable {
    case negotiate       = 0x0000
    case sessionSetup    = 0x0001
    case logoff          = 0x0002
    case treeConnect     = 0x0003
    case treeDisconnect  = 0x0004
    case create          = 0x0005
    case close           = 0x0006
    case flush           = 0x0007
    case read            = 0x0008
    case write           = 0x0009
    case lock            = 0x000A
    case ioctl           = 0x000B
    case cancel          = 0x000C
    case echo            = 0x000D
    case queryDirectory  = 0x000E
    case changeNotify    = 0x000F
    case queryInfo       = 0x0010
    case setInfo         = 0x0011
    case oplockBreak     = 0x0012
}

// MARK: - Dialects

public enum SMB2Dialect: UInt16, Sendable {
    case smb202 = 0x0202
    case smb21  = 0x0210
    case smb30  = 0x0300
    case smb302 = 0x0302
    case smb311 = 0x0311
    /// Wildcard sent in a multi-protocol negotiate; we answer with 2.1.
    case wildcard2ff = 0x02FF
}

// MARK: - Header flags ([MS-SMB2] §2.2.1.2)

public struct SMB2HeaderFlags: OptionSet, Sendable {
    public let rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }

    public static let serverToRedir   = SMB2HeaderFlags(rawValue: 0x0000_0001) // RESPONSE
    public static let asyncCommand    = SMB2HeaderFlags(rawValue: 0x0000_0002)
    public static let relatedOps      = SMB2HeaderFlags(rawValue: 0x0000_0004) // compound chaining
    public static let signed          = SMB2HeaderFlags(rawValue: 0x0000_0008)
    public static let priorityMask    = SMB2HeaderFlags(rawValue: 0x0000_0070)
    public static let dfsOperation    = SMB2HeaderFlags(rawValue: 0x1000_0000)
}

// MARK: - NTSTATUS (the subset we return)

public enum NTStatus: UInt32, Sendable {
    case success                = 0x0000_0000
    case pending                = 0x0000_0103
    case notifyEnumDir          = 0x0000_010C
    case noMoreFiles            = 0x8000_0006
    case endOfFile              = 0xC000_0011
    case moreProcessingRequired = 0xC000_0016
    case unsuccessful           = 0xC000_0001
    case notImplemented         = 0xC000_0002
    case invalidParameter       = 0xC000_000D
    case noSuchFile             = 0xC000_000F
    case accessDenied           = 0xC000_0022
    case objectNameInvalid      = 0xC000_0033
    case objectNameNotFound     = 0xC000_0034
    case objectNameCollision    = 0xC000_0035
    case objectPathNotFound     = 0xC000_003A
    case sharingViolation       = 0xC000_0043
    case fileIsADirectory       = 0xC000_00BA
    case directoryNotEmpty      = 0xC000_0101
    case notADirectory          = 0xC000_0103
    case notSupported           = 0xC000_00BB
    case cancelled              = 0xC000_0120
    case cannotDelete           = 0xC000_0121
    case fileClosed             = 0xC000_0128
    case fileLockConflict       = 0xC000_0054
    case rangeNotLocked         = 0xC000_007E
    case lockNotGranted         = 0xC000_0055
    case diskFull               = 0xC000_007F
    case bufferTooSmall         = 0xC000_0023
    case infoLengthMismatch     = 0xC000_0004
    case logonFailure           = 0xC000_006D
    case networkNameDeleted     = 0xC000_00C9
    case badNetworkName         = 0xC000_00CC
    case userSessionDeleted     = 0xC000_0203
}

// MARK: - The 64-byte SMB2 packet header ([MS-SMB2] §2.2.1.2, SYNC form)

/// A decoded SMB2 header. The 16-byte async form (§2.2.1.1) overlays TreeId +
/// reserved with a 64-bit AsyncId; we only *emit* async headers (for interim
/// CHANGE_NOTIFY replies) and never receive them, so this models the sync form
/// and carries an optional AsyncId used only on the encode path.
public struct SMB2Header: Sendable {
    public static let size = 64
    public static let protocolId: [UInt8] = [0xFE, 0x53, 0x4D, 0x42] // 0xFE 'S' 'M' 'B'

    public var creditCharge: UInt16
    public var status: UInt32          // request: channel-sequence/reserved; response: NTSTATUS
    public var command: SMB2Command
    public var creditReqGrant: UInt16  // request: credits requested; response: credits granted
    public var flags: SMB2HeaderFlags
    public var nextCommand: UInt32     // byte offset to the next header in a compound, or 0
    public var messageId: UInt64
    public var treeId: UInt32
    public var sessionId: UInt64
    public var asyncId: UInt64         // only meaningful when flags contains .asyncCommand
    public var signature: Data         // 16 bytes (zero when unsigned)

    public init(command: SMB2Command,
                messageId: UInt64 = 0,
                creditCharge: UInt16 = 1,
                creditReqGrant: UInt16 = 0,
                status: UInt32 = 0,
                flags: SMB2HeaderFlags = [],
                nextCommand: UInt32 = 0,
                treeId: UInt32 = 0,
                sessionId: UInt64 = 0,
                asyncId: UInt64 = 0,
                signature: Data = Data(count: 16)) {
        self.command = command
        self.messageId = messageId
        self.creditCharge = creditCharge
        self.creditReqGrant = creditReqGrant
        self.status = status
        self.flags = flags
        self.nextCommand = nextCommand
        self.treeId = treeId
        self.sessionId = sessionId
        self.asyncId = asyncId
        self.signature = signature
    }

    /// Decode a 64-byte SYNC header from `r` at its current offset.
    public static func decode(_ r: inout ByteReader) throws -> SMB2Header {
        let proto = try r.take(4)
        guard [UInt8](proto) == protocolId else { throw WireError.malformed("bad SMB2 protocol id") }
        let structureSize = try r.u16()
        guard structureSize == 64 else { throw WireError.malformed("SMB2 header StructureSize != 64") }
        let creditCharge = try r.u16()
        let status = try r.u32()
        guard let command = SMB2Command(rawValue: try r.u16()) else { throw WireError.malformed("unknown SMB2 command") }
        let credits = try r.u16()
        let flags = SMB2HeaderFlags(rawValue: try r.u32())
        let next = try r.u32()
        let mid = try r.u64()
        // The next 8 bytes are Reserved(4)+TreeId(4) in a SYNC header, or a 64-bit
        // AsyncId in an ASYNC header (which the client uses on CANCEL of a pending op).
        let lo = try r.u32()
        let hi = try r.u32()
        let sessionId = try r.u64()
        let signature = try r.take(16)
        var h = SMB2Header(command: command, messageId: mid, creditCharge: creditCharge,
                           creditReqGrant: credits, status: status, flags: flags,
                           nextCommand: next, treeId: hi, sessionId: sessionId,
                           signature: signature)
        if flags.contains(.asyncCommand) {
            h.asyncId = UInt64(lo) | (UInt64(hi) << 32)
            h.treeId = 0
        }
        return h
    }

    /// Encode this header (64 bytes). Emits the async layout when `flags` contains
    /// `.asyncCommand` (AsyncId overlays Reserved+TreeId), else the sync layout.
    public func encode(into w: inout ByteWriter) {
        w.bytes(SMB2Header.protocolId)
        w.u16(64)                       // StructureSize
        w.u16(creditCharge)
        w.u32(status)
        w.u16(command.rawValue)
        w.u16(creditReqGrant)
        w.u32(flags.rawValue)
        w.u32(nextCommand)
        w.u64(messageId)
        if flags.contains(.asyncCommand) {
            w.u64(asyncId)              // §2.2.1.1: AsyncId occupies Reserved+TreeId
        } else {
            w.u32(0)                    // Reserved
            w.u32(treeId)
        }
        w.u64(sessionId)
        let sig = signature.count == 16 ? signature : Data(count: 16)
        w.bytes(sig)
    }
}

// MARK: - File attributes / access (subset)

public enum FileAttributes {
    public static let readonly:  UInt32 = 0x0000_0001
    public static let hidden:    UInt32 = 0x0000_0002
    public static let directory: UInt32 = 0x0000_0010
    public static let normal:    UInt32 = 0x0000_0080
}

// MARK: - FileSystem attribute flags (FileFsAttributeInformation)

public enum FSAttributeFlags {
    public static let caseSensitiveSearch: UInt32 = 0x0000_0001
    public static let casePreservedNames:  UInt32 = 0x0000_0002
    public static let unicodeOnDisk:        UInt32 = 0x0000_0004
    public static let namedStreams:         UInt32 = 0x0004_0000
}

// MARK: - Negotiate capabilities (server-advertised subset)

public enum SMB2Capabilities {
    public static let dfs:       UInt32 = 0x0000_0001
    public static let leasing:   UInt32 = 0x0000_0002   // deliberately NOT advertised
    public static let largeMTU:  UInt32 = 0x0000_0004   // enables multi-credit 1 MiB I/O on 2.1
}
