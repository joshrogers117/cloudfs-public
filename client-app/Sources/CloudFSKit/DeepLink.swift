// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - cloudfs:// deep links (API.md §6)
//
//   cloudfs://item/<spaceId>/<inodeId>[?select=0]  (stable team link)
//   cloudfs://<spaceId>                           (filespace root)
//   cloudfs://<spaceId>/<path>[?select=0]          (legacy path link)
//
// - spaceId is the URL host; each path segment is URL-encoded.
// - Path is POSIX-style within the space.
// - ?select=0 means "reveal the enclosing folder" instead of select-in-Finder
//   (select is the default).
// - This is a navigation aid, NOT a credential — it grants nothing. The recipient
//   client resolves the path and permission-checks via the gateway before reveal.

public enum DeepLink {

    public static let scheme = "cloudfs"

    /// Build a `cloudfs://` URL from a space id and a POSIX-style path.
    /// `select == false` appends `?select=0` (reveal enclosing folder).
    public static func build(spaceId: String, path: String, select: Bool = true) -> String {
        let host = spaceId.addingPercentEncoding(withAllowedCharacters: hostAllowed) ?? spaceId
        let segments = path.split(separator: "/").map { seg in
            seg.addingPercentEncoding(withAllowedCharacters: segmentAllowed) ?? String(seg)
        }
        var url = "\(scheme)://\(host)"
        if !segments.isEmpty { url += "/" + segments.joined(separator: "/") }
        if !select { url += "?select=0" }
        return url
    }

    /// Stable item identity. Resolution belongs to the recipient's authorized
    /// daemon, so rename and different folder-root projections do not change it.
    public static func buildItem(spaceId: String, itemId: String, select: Bool = true) -> String {
        let space = spaceId.addingPercentEncoding(withAllowedCharacters: segmentAllowed) ?? spaceId
        let item = itemId.addingPercentEncoding(withAllowedCharacters: segmentAllowed) ?? itemId
        return "\(scheme)://item/\(space)/\(item)" + (select ? "" : "?select=0")
    }

    public struct Parsed: Sendable, Equatable {
        public let spaceId: String
        /// POSIX-style decoded path within the space (no leading slash).
        public let path: String
        /// false when `?select=0` was present.
        public let select: Bool
        /// Present only for a stable item link; never interpreted as a local path.
        public let itemId: String?
        public init(spaceId: String, path: String, select: Bool, itemId: String? = nil) {
            self.spaceId = spaceId; self.path = path; self.select = select; self.itemId = itemId
        }
    }

    /// Parse a navigation link. Decode each segment exactly once, before checking
    /// it: escaped slashes and dot segments must never turn into filesystem traversal.
    public static func parse(_ string: String) -> Parsed? {
        guard let comps = URLComponents(string: string),
              comps.scheme?.lowercased() == scheme,
              comps.user == nil, comps.password == nil, comps.port == nil,
              comps.fragment == nil,
              let host = comps.host, validSegment(host),
              host != "auth", host != "connect"
        else { return nil }
        let queries = comps.queryItems ?? []
        guard queries.count <= 1,
              queries.allSatisfy({ $0.name == "select" && ($0.value == "0" || $0.value == "1") })
        else { return nil }
        var encodedPath = comps.percentEncodedPath
        if encodedPath.hasPrefix("/") { encodedPath.removeFirst() }
        var segments: [String] = []
        if !encodedPath.isEmpty {
            for raw in encodedPath.split(separator: "/", omittingEmptySubsequences: false) {
                guard let segment = String(raw).removingPercentEncoding, validSegment(segment) else { return nil }
                segments.append(segment)
            }
        }
        if host == "item" {
            guard segments.count == 2 else { return nil }
            return Parsed(spaceId: segments[0], path: "", select: queries.first?.value != "0", itemId: segments[1])
        }
        // Finder versions before the unified link format used a reserved `file` host.
        let spaceId: String
        if host == "file" {
            guard !segments.isEmpty else { return nil }
            spaceId = segments.removeFirst()
        } else {
            spaceId = host
        }
        return Parsed(spaceId: spaceId, path: segments.joined(separator: "/"),
                      select: queries.first?.value != "0")
    }

    /// Resolve only inside the mounted volume, including after symlink resolution.
    /// The caller must use a mount belonging to an already authorized filespace.
    /// This does filesystem work; callers should run it away from the main actor.
    public static func resolve(_ link: Parsed, mountPath: String) -> URL? {
        guard link.itemId == nil, mountPath.hasPrefix("/"), !mountPath.contains("\0"),
              validSegment(link.spaceId),
              link.path.isEmpty || link.path.split(separator: "/", omittingEmptySubsequences: false)
                .allSatisfy({ validSegment(String($0)) }) else { return nil }
        let root = URL(fileURLWithPath: mountPath, isDirectory: true).standardizedFileURL.resolvingSymlinksInPath()
        guard root.path != "/" else { return nil }
        var target = root
        for segment in link.path.split(separator: "/") {
            // Resolve existing parents individually as Foundation leaves a whole
            // nonexistent leaf path unresolved (including its symlink parents).
            target = target.appendingPathComponent(String(segment))
                .standardizedFileURL.resolvingSymlinksInPath()
            guard target.path == root.path || target.path.hasPrefix(root.path + "/") else { return nil }
        }
        return target
    }

    private static func validSegment(_ value: String) -> Bool {
        !value.isEmpty && value != "." && value != ".." &&
        value.rangeOfCharacter(from: .controlCharacters) == nil &&
        !value.contains("/") && !value.contains("\\")
    }

    // Allowed character sets (encode the reserved separators).
    private static let segmentAllowed: CharacterSet = {
        var cs = CharacterSet.urlPathAllowed
        cs.remove(charactersIn: "/?#%")
        return cs
    }()
    private static let hostAllowed: CharacterSet = {
        var cs = CharacterSet.urlHostAllowed
        cs.remove(charactersIn: "/?#%")
        return cs
    }()
}
