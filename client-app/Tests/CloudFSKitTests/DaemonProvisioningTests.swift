// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// M7 — the app→daemon config hand-off: daemon.env + 0600 token in the rendezvous dir.
@Suite struct DaemonProvisioningTests {

    @Test func provisionWritesEnvAndLockedToken() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("cfs-prov-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let socket = try DaemonProvisioning.provision(
            gatewayURL: "https://gateway.example.invalid",
            token: "secret-token", root: root,
            finderSocketPath: "/tmp/test-finder.sock")

        #expect(socket == root.appendingPathComponent("d.sock").path)

        let env = try String(contentsOf: root.appendingPathComponent("daemon.env"), encoding: .utf8)
        #expect(env.contains("CLOUDFS_GATEWAY=https://gateway.example.invalid"))
        #expect(env.contains("CLOUDFS_SOCKET=\(socket)"))
        #expect(env.contains("CLOUDFS_TOKEN_FILE=\(root.appendingPathComponent("token.txt").path)"))
        // The cipher's master key location — reads/writes fail without it (the key
        // itself is operator-provisioned; provisioning only points the daemon at it).
        #expect(env.contains("CLOUDFS_KEY_FILE=\(root.appendingPathComponent("key.hex").path)"))
        #expect(env.contains("CLOUDFS_KEY_FILE_OPTIONAL=1"))
        // M8 — the appex-reachable second control socket; omitted entirely when nil.
        #expect(env.contains("CLOUDFS_FINDER_SOCKET=/tmp/test-finder.sock"))
        #expect(!DaemonProvisioning.envFileContents(gatewayURL: "https://x", root: root,
                                                    finderSocketPath: nil)
            .contains("CLOUDFS_FINDER_SOCKET"))
        #expect(env.hasSuffix("\n"), "trailing newline so appended lines can't glue onto the last key")

        let tokenPath = root.appendingPathComponent("token.txt").path
        #expect(try String(contentsOfFile: tokenPath, encoding: .utf8) == "secret-token")
        let mode = try FileManager.default.attributesOfItem(atPath: tokenPath)[.posixPermissions] as? Int
        #expect(mode == 0o600, "the bearer token must be owner-only")
    }

    @Test func reprovisionOverwritesIdempotently() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("cfs-prov-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        _ = try DaemonProvisioning.provision(gatewayURL: "https://a.example", token: "t1", root: root)
        _ = try DaemonProvisioning.provision(gatewayURL: "https://b.example", token: "t2", root: root)

        let env = try String(contentsOf: root.appendingPathComponent("daemon.env"), encoding: .utf8)
        #expect(env.contains("https://b.example"))
        #expect(!env.contains("https://a.example"))
        #expect(try String(contentsOf: root.appendingPathComponent("token.txt"), encoding: .utf8) == "t2")
    }

    @Test func reprovisionDropsLocalKeyBindingWhenGatewayChanges() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("cfs-prov-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        _ = try DaemonProvisioning.provision(gatewayURL: "https://a.example", token: provisionToken(org: "org1"), root: root,
                                             finderSocketPath: nil, keyFileFilespace: "edit1")
        _ = try DaemonProvisioning.provision(gatewayURL: "https://b.example", token: provisionToken(org: "org1"), root: root,
                                             finderSocketPath: nil)

        let env = try String(contentsOf: root.appendingPathComponent("daemon.env"), encoding: .utf8)
        #expect(!env.contains("CLOUDFS_KEY_FILE_FILESPACE="), "a key binding must not survive a gateway change")
        #expect(!env.contains("CLOUDFS_KEY_FILE_GATEWAY="))
    }

    @Test func reprovisionPreservesBindingForSameNormalizedGateway() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("cfs-prov-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        _ = try DaemonProvisioning.provision(gatewayURL: "https://gw.example/", token: provisionToken(org: "org1"), root: root,
                                             finderSocketPath: nil, keyFileFilespace: "edit1")
        _ = try DaemonProvisioning.provision(gatewayURL: "https://GW.EXAMPLE:443", token: provisionToken(org: "org1"), root: root,
                                             finderSocketPath: nil)

        let env = try String(contentsOf: root.appendingPathComponent("daemon.env"), encoding: .utf8)
        #expect(env.contains("CLOUDFS_KEY_FILE_FILESPACE=edit1"))
        #expect(env.contains("CLOUDFS_KEY_FILE_GATEWAY=https://gw.example"))
        #expect(env.contains("CLOUDFS_KEY_FILE_ORG=org1"))
    }

    @Test func reprovisionDropsBindingWhenOrganizationChanges() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("cfs-prov-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        _ = try DaemonProvisioning.provision(gatewayURL: "https://gw.example", token: provisionToken(org: "org1"), root: root,
                                             finderSocketPath: nil, keyFileFilespace: "edit1")
        _ = try DaemonProvisioning.provision(gatewayURL: "https://gw.example", token: provisionToken(org: "org2"), root: root,
                                             finderSocketPath: nil)

        let env = try String(contentsOf: root.appendingPathComponent("daemon.env"), encoding: .utf8)
        #expect(!env.contains("CLOUDFS_KEY_FILE_FILESPACE="), "the same filespace ID on another org must not retain the local key binding")
    }
}

private func provisionToken(org: String) -> String {
    let payload = Data("{\"org\":\"\(org)\"}".utf8).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    return "header.\(payload).signature"
}

@Suite struct ExistingDaemonProvisioningTests {
    @Test func reuseRequiresAnExactServerAndNonemptyCredential() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let server = "https://workspace.example.test"
        #expect(DaemonProvisioning.existingToken(gatewayURL: server, root: root) == nil)
        try DaemonProvisioning.provision(gatewayURL: server, token: "fixture-token", root: root, finderSocketPath: nil)
        #expect(DaemonProvisioning.existingToken(gatewayURL: server, root: root) == "fixture-token")
        #expect(DaemonProvisioning.existingToken(gatewayURL: server + ".evil", root: root) == nil)
        try "   ".write(to: root.appendingPathComponent("token.txt"), atomically: true, encoding: .utf8)
        #expect(DaemonProvisioning.existingToken(gatewayURL: server, root: root) == nil)
    }
}
