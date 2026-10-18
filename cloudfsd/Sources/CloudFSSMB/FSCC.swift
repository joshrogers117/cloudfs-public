// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB — [MS-FSCC] information-class constants + the attribute synthesis the
// handlers share. Timestamps are SYNTHESIZED from contentVersion here (as the NFS
// backend does); P3 replaces this with real created/modified times from the
// gateway. Mode is owner-only (single-user volume): dirs 0700, files 0600.

import Foundation
import CloudFSCore

// MARK: - CREATE dispositions ([MS-SMB2] §2.2.13)

public enum CreateDisposition: UInt32 {
    case supersede   = 0
    case open        = 1
    case create      = 2
    case openIf      = 3
    case overwrite   = 4
    case overwriteIf = 5
}

// MARK: - CREATE options / oplock

public enum CreateOptions {
    public static let directoryFile: UInt32   = 0x0000_0001
    public static let nonDirectoryFile: UInt32 = 0x0000_0040
    public static let deleteOnClose: UInt32   = 0x0000_1000
}

// MARK: - QUERY_INFO InfoType ([MS-SMB2] §2.2.37)

public enum InfoType: UInt8 {
    case file       = 0x01
    case fileSystem = 0x02
    case security   = 0x03
    case quota      = 0x04
}

// MARK: - FILE information classes ([MS-FSCC] §2.4)

public enum FileInfoClass: UInt8 {
    case directoryInformation       = 0x01
    case fullDirectoryInformation   = 0x02
    case bothDirectoryInformation   = 0x03
    case basicInformation           = 0x04
    case standardInformation        = 0x05
    case internalInformation        = 0x06
    case eaInformation              = 0x07
    case nameInformation            = 0x09
    case positionInformation        = 0x0E
    case allInformation             = 0x12
    case alignmentInformation       = 0x11
    case idBothDirectoryInformation = 0x25   // 37 — the one the mac client uses
    case networkOpenInformation     = 0x22   // 34
    case attributeTagInformation    = 0x23   // 35
}

// MARK: - FILESYSTEM information classes ([MS-FSCC] §2.5)

public enum FsInfoClass: UInt8 {
    case volumeInformation   = 0x01
    case sizeInformation     = 0x03
    case deviceInformation   = 0x04
    case attributeInformation = 0x05
    case fullSizeInformation = 0x07
}

// MARK: - Attribute synthesis

public enum SMBAttrs {
    /// DOS read-only is content protection, not an ACL and not a POSIX mode.
    /// Directory read-only bits do not restrict child creation.
    public static func isReadOnly(_ meta: ItemMetadata) -> Bool {
        !meta.isDir && (meta.fileAttributes ?? 0) & FileAttributes.readonly != 0
    }

    /// FILE_ATTRIBUTE for an item: DIRECTORY for dirs, NORMAL for files.
    public static func fileAttributes(isDir: Bool, stored: UInt32? = nil) -> UInt32 {
        let attributes = (stored ?? 0) | (isDir ? FileAttributes.directory : 0)
        return attributes == 0 ? FileAttributes.normal : attributes
    }

    /// A deterministic pseudo-timestamp (Windows FILETIME) derived from
    /// `contentVersion` via FNV-1a, matching the NFS backend's trick: the time
    /// moves iff content changes, so the client's (mtime,size) cache validation
    /// stays correct. Base epoch 2020-01-01. Replaced by real times in P3.
    public static func synthTime(_ contentVersion: String) -> UInt64 {
        var hash: UInt64 = 0xcbf2_9ce4_8422_2325
        for b in contentVersion.utf8 {
            hash ^= UInt64(b)
            hash = hash &* 0x0000_0100_0000_01B3
        }
        let base2020: Double = 1_577_836_800   // 2020-01-01T00:00:00Z (unix)
        let spread = Double(hash % 63_072_000)  // up to ~2 years of spread
        return filetime(unixSeconds: base2020 + spread)
    }

    /// Prefer a real wall-clock time; fall back to the deterministic synthesis so
    /// legacy (pre-v13) rows still present a stable, content-correlated date.
    public static func time(_ real: Date?, contentVersion: String) -> UInt64 {
        if let real { return filetime(unixSeconds: real.timeIntervalSince1970) }
        return synthTime(contentVersion)
    }

    /// The four SMB times for an item: (creation, lastAccess, lastWrite, change).
    /// created→creation; modified→write/access/change (we have no separate atime).
    public static func times(created: Date?, modified: Date?, accessed: Date? = nil, changed: Date? = nil, contentVersion: String)
        -> (creation: UInt64, access: UInt64, write: UInt64, change: UInt64) {
        let m = time(modified, contentVersion: contentVersion)
        let c = time(created ?? modified, contentVersion: contentVersion)
        return (c, accessed.map { time($0, contentVersion: contentVersion) } ?? m, m, changed.map { time($0, contentVersion: contentVersion) } ?? m)
    }

    /// Allocation size: round file size up to the 1 MiB block.
    public static func allocationSize(_ size: Int) -> UInt64 {
        let blk = kDefaultBlockSize
        let rounded = ((size + blk - 1) / blk) * blk
        return UInt64(rounded)
    }
}

// MARK: - Create-context names ([MS-SMB2] §2.2.13.2 + Apple AAPL)

public enum CreateContextName {
    public static let maxAccess = "MxAc"
    public static let aapl      = "AAPL"
    public static let queryOnDiskId = "QFid"
}

// MARK: - AAPL server-query bits (Apple smb_2.h)

public enum AAPL {
    public static let commandServerQuery: UInt32 = 1
    public static let commandResolveId:   UInt32 = 2

    // request/reply bitmap
    public static let bitmapServerCaps: UInt64 = 0x01
    public static let bitmapVolumeCaps: UInt64 = 0x02
    public static let bitmapModelInfo:  UInt64 = 0x04

    // server capabilities
    public static let capSupportsReadDirAttr: UInt64 = 0x01
    public static let capSupportsOSXCopyfile: UInt64 = 0x02
    public static let capUnixBased:           UInt64 = 0x04
    public static let capSupportsNFSAce:      UInt64 = 0x08

    // volume capabilities
    public static let volSupportResolveId: UInt64 = 0x01
    public static let volCaseSensitive:    UInt64 = 0x02
    public static let volSupportsFullSync: UInt64 = 0x04
}

extension SMBAttrs {
    /// MS-FSCC FileBasicInformation. Zero means unchanged. Handle-scoped -1/-2
    /// automatic-time controls and unsupported DOS attributes fail explicitly.
    static func parseBasicInfo(_ bytes: Data, isDir: Bool) throws -> BasicFileInfo {
        guard bytes.count == 40 else { throw EngineError(.invalidParams, "FileBasicInformation must contain 40 bytes") }
        var r = ByteReader(bytes)
        func date(_ raw: UInt64) throws -> Date? {
            if raw == 0 { return nil }
            if raw == UInt64.max || raw == UInt64.max - 1 { throw EngineError(.unimplemented, "Handle-scoped timestamp controls are unsupported") }
            guard raw <= 2_650_467_743_999_990_000 else { throw EngineError(.invalidParams, "Invalid file timestamp") }
            return Date(timeIntervalSince1970: Double(raw) / 10_000_000 - 11_644_473_600)
        }
        let created = try date(r.u64()), accessed = try date(r.u64()), modified = try date(r.u64()), changed = try date(r.u64())
        let attributes = try r.u32()
        guard attributes & ~(UInt32(0x2127) | FileAttributes.directory | FileAttributes.normal) == 0 else {
            throw EngineError(.unimplemented, "Unsupported file attributes")
        }
        guard attributes & FileAttributes.directory == 0 || isDir else { throw EngineError(.invalidParams, "Cannot turn a file into a directory") }
        return BasicFileInfo(createdAt: created, modifiedAt: modified, accessedAt: accessed, changedAt: changed,
                             fileAttributes: attributes == 0 ? nil : attributes & 0x2127)
    }
}
