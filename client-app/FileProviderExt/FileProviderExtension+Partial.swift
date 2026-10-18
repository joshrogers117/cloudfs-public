// SPDX-License-Identifier: AGPL-3.0-or-later
import FileProvider
import os

// ============================================================================
// Byte-range streaming — the "feels local" path AND the #1 watchdog risk.
//
// `NSFileProviderPartialContentFetching` lets Finder/NLEs read an arbitrary range of a
// huge media file without materializing the whole thing. macOS may kill a slow ranged
// read as a "stalled drive"; the spike measured a comfortable margin on R2, and routing
// the fetch to the daemon's warm cache keeps repeat scrubs instant.
//
// The daemon does the real work (snap to block boundaries, cache HIT/MISS, decrypt) and
// hands back a file of decrypted bytes packed from offset 0 plus the absolute range it
// covers. We re-place those bytes at their absolute offset (see `materialize`).
// ============================================================================

extension FileProviderExtension: NSFileProviderPartialContentFetching {

    func fetchPartialContents(
        for itemIdentifier: NSFileProviderItemIdentifier,
        version requestedVersion: NSFileProviderItemVersion,
        request: NSFileProviderRequest,
        minimalRange requestedRange: NSRange,
        aligningTo alignment: Int,
        options: NSFileProviderFetchContentsOptions = [],
        completionHandler: @escaping (URL?, NSFileProviderItem?, NSRange, NSFileProviderMaterializationFlags, Error?) -> Void
    ) -> Progress {
        let progress = Progress(totalUnitCount: 100)
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            do {
                let meta = try dataPath.lookup(itemIdentifier.rawValue)
                let item = CloudFSItem(meta)
                let version = contentVersionString(requestedVersion) ?? meta.contentVersion
                // Hand the requested range + the system's alignment straight to the daemon; it
                // snaps outward to block boundaries (our 1 MiB blocks) and returns what it fetched.
                let range = try dataPath.readRange(itemId: itemIdentifier.rawValue, version: version,
                                                   offset: requestedRange.location,
                                                   length: max(requestedRange.length, 1),
                                                   alignment: alignment)
                let dest = try materialize(range, into: temporaryDirectory())
                let got = NSRange(location: range.offset, length: range.length)
                progress.completedUnitCount = 100
                completionHandler(dest, item, got, [], nil)
            } catch {
                log.error("fetchPartialContents \(itemIdentifier.rawValue, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
                completionHandler(nil, nil, NSRange(location: 0, length: 0), [], error)
            }
        }
        return progress
    }
}
