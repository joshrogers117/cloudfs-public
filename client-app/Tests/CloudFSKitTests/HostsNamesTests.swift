// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
@testable import CloudFSKit

// M5 — the managed /etc/hosts block: pure string logic, fully covered here; only
// the privileged write happens outside tests.
@Suite struct HostsNamesTests {

    @Test func labelsAreDNSSafeAndMatchDaemonRules() {
        #expect(HostsNames.label(for: "Edit 1") == "Edit-1")
        #expect(HostsNames.label(for: "Mac Test") == "Mac-Test")
        #expect(HostsNames.label(for: "  weird!!name  ") == "weird-name")
        #expect(HostsNames.label(for: "***") == "cloudfs")
    }

    @Test func managedBlockIsSortedAndDeduped() {
        let block = HostsNames.managedBlock(filespaceNames: ["Mac Test", "Edit 1", "Edit 1"])
        #expect(block == """
        # BEGIN cloud-fs managed names
        127.0.0.1 Edit-1
        127.0.0.1 Mac-Test
        # END cloud-fs managed names
        """)
        #expect(HostsNames.managedBlock(filespaceNames: []) == "")
    }

    @Test func mergeInsertsReplacesAndRemovesIdempotently() {
        let base = "127.0.0.1 localhost\n255.255.255.255 broadcasthost\n"

        let v1 = HostsNames.merged(hostsContent: base, filespaceNames: ["Edit 1"])
        #expect(v1.contains("127.0.0.1 Edit-1"))
        #expect(v1.contains("localhost"))

        // Re-apply with different names REPLACES the block (no duplication).
        let v2 = HostsNames.merged(hostsContent: v1, filespaceNames: ["Mac Test"])
        #expect(!v2.contains("Edit-1"))
        #expect(v2.contains("127.0.0.1 Mac-Test"))
        #expect(v2.components(separatedBy: HostsNames.beginMarker).count == 2, "exactly one block")

        // Applying twice with the same names is byte-stable.
        let v3 = HostsNames.merged(hostsContent: v2, filespaceNames: ["Mac Test"])
        #expect(v3 == v2)

        // Empty names removes the block entirely, restoring (almost) the base.
        let v4 = HostsNames.merged(hostsContent: v2, filespaceNames: [])
        #expect(!v4.contains(HostsNames.beginMarker))
        #expect(v4.contains("localhost"))
    }

    @Test func shellCommandStripsThenAppends() {
        let cmd = HostsNames.shellCommand(filespaceNames: ["Edit 1"])
        #expect(cmd.contains("sed -i ''"))
        #expect(cmd.contains("/etc/hosts"))
        #expect(cmd.contains("printf"))
        #expect(cmd.contains("127.0.0.1 Edit-1"))
        // Removal form: strip only.
        let rm = HostsNames.shellCommand(filespaceNames: [])
        #expect(rm.contains("sed") && !rm.contains("printf"))
    }
}
