// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - HostsNames — bare sidebar names via a managed /etc/hosts block (M5)
//
// Finder's sidebar shows the SERVER NAME of a network mount. Bonjour names must
// end in ".local"; a BARE name ("Edit-1") needs a hosts-file line, which needs
// admin rights exactly once. The app maintains ONE clearly-marked block:
//
//   # BEGIN cloud-fs managed names
//   127.0.0.1 Edit-1
//   127.0.0.1 Mac-Test
//   # END cloud-fs managed names
//
// replaced wholesale on every apply (idempotent; removing all names removes the
// block). Everything here is pure string work so it is fully unit-tested; the
// privileged write itself happens in the app via the macOS admin-auth dialog.

public enum HostsNames {

    public static let beginMarker = "# BEGIN cloud-fs managed names"
    public static let endMarker = "# END cloud-fs managed names"

    /// DNS-safe label for a filespace display name ("Edit 1" → "Edit-1").
    /// MUST stay in lock-step with the daemon's BonjourHostname.label(for:) —
    /// the daemon mounts from exactly this label when it resolves.
    public static func label(for filespaceName: String) -> String {
        let mapped = filespaceName.map { ch -> Character in
            ch.isLetter || ch.isNumber ? ch : "-"
        }
        let collapsed = String(mapped).split(separator: "-", omittingEmptySubsequences: true)
            .joined(separator: "-")
        return collapsed.isEmpty ? "cloudfs" : String(collapsed.prefix(63))
    }

    /// The managed block for a set of filespace names (sorted, deduped labels).
    /// Empty input → empty string (no block at all).
    public static func managedBlock(filespaceNames: [String]) -> String {
        let labels = Set(filespaceNames.map(label(for:))).sorted()
        guard !labels.isEmpty else { return "" }
        let lines = labels.map { "127.0.0.1 \($0)" }
        return ([beginMarker] + lines + [endMarker]).joined(separator: "\n")
    }

    /// Replace (or insert/remove) the managed block within existing hosts content.
    public static func merged(hostsContent: String, filespaceNames: [String]) -> String {
        var lines = hostsContent.components(separatedBy: "\n")
        if let begin = lines.firstIndex(of: beginMarker) {
            let end = lines[begin...].firstIndex(of: endMarker) ?? begin
            lines.removeSubrange(begin...min(end, lines.count - 1))
            // Drop a now-dangling blank separator left where the block was.
            if begin < lines.count, begin > 0, lines[begin].isEmpty, lines[begin - 1].isEmpty {
                lines.remove(at: begin)
            }
        }
        var out = lines.joined(separator: "\n")
        let block = managedBlock(filespaceNames: filespaceNames)
        if !block.isEmpty {
            if !out.hasSuffix("\n") { out += "\n" }
            out += block + "\n"
        }
        return out
    }

    /// The POSIX shell command the privileged step runs: strip any previous managed
    /// block, then append the new one. Labels are DNS-safe ([A-Za-z0-9-]), so the
    /// printf payload needs no quoting gymnastics.
    public static func shellCommand(filespaceNames: [String]) -> String {
        let strip = "sed -i '' '/^\(beginMarker)$/,/^\(endMarker)$/d' /etc/hosts"
        let block = managedBlock(filespaceNames: filespaceNames)
        guard !block.isEmpty else { return strip }
        let printfArg = block.replacingOccurrences(of: "\n", with: "\\n")
        return "\(strip) && printf '\(printfArg)\\n' >> /etc/hosts"
    }
}
