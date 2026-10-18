// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB — named streams (SMB alternate data streams = macOS xattrs / Apple
// metadata forks). The macOS smbfs client maps xattrs onto SMB streams:
//   com.apple.ResourceFork  ↔ stream "AFP_Resource"
//   com.apple.FinderInfo    ↔ stream "AFP_AfpInfo"  (a 60-byte AfpInfo blob whose
//                             32-byte FinderInfo sits at offset 16)
//   every other xattr       ↔ a same-named stream
// The wrapping/unwrapping is the CLIENT's job; the server stores the stream bytes
// verbatim and keys them by the on-wire stream name. Storing these natively is
// what keeps macOS from spraying AppleDouble `._` sidecar FILES into the store.

import Foundation

public enum StreamName {
    public static let afpResource = "AFP_Resource"
    public static let afpInfo     = "AFP_AfpInfo"
    /// The AfpInfo blob is 60 bytes with FinderInfo (32 bytes) at offset 16.
    public static let afpInfoSize = 60
    public static let finderInfoOffset = 16
    public static let finderInfoSize = 32
}

/// The result of parsing an SMB CREATE path that may address a named stream:
/// `"dir\\file.txt:xattrname:$DATA"` → base `"dir\\file.txt"`, stream `"xattrname"`.
public struct StreamPath: Sendable {
    public let base: String
    public let stream: String?   // nil = the file's main (unnamed) data stream
}

public enum SMBStreams {
    /// Split an SMB create path into (base file path, optional stream name).
    /// SMB stream syntax: `path[:streamName[:streamType]]`. The unnamed data
    /// stream is `path` or `path::$DATA`. We only support `$DATA`-type streams.
    /// The path portion may itself contain no colon (colons are illegal in names,
    /// enforced elsewhere), so the FIRST colon starts the stream section.
    public static func parse(_ createName: String) -> StreamPath {
        guard let colon = createName.firstIndex(of: ":") else {
            return StreamPath(base: createName, stream: nil)
        }
        let base = String(createName[createName.startIndex..<colon])
        var rest = String(createName[createName.index(after: colon)...])
        // Strip a trailing ":$DATA" (or ":$Data") stream-type suffix.
        if let typeColon = rest.range(of: ":", options: .backwards) {
            let type = rest[typeColon.upperBound...]
            if type.uppercased() == "$DATA" || type.isEmpty {
                rest = String(rest[rest.startIndex..<typeColon.lowerBound])
            }
        }
        // `path::$DATA` → empty stream name → the unnamed data stream.
        return StreamPath(base: base, stream: rest.isEmpty ? nil : rest)
    }

    /// True when an AFP_AfpInfo write carries an all-zero FinderInfo, the client's
    /// convention for "clear the FinderInfo" — which we honor by deleting the stream.
    public static func isEmptyAfpInfo(_ name: String, _ data: Data) -> Bool {
        guard name == StreamName.afpInfo, data.count >= StreamName.finderInfoOffset + StreamName.finderInfoSize
        else { return false }
        let lo = data.startIndex + StreamName.finderInfoOffset
        let hi = lo + StreamName.finderInfoSize
        return data[lo..<hi].allSatisfy { $0 == 0 }
    }
}
