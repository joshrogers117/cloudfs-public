// swift-tools-version: 6.1
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// cloudfsd — the local filesystem engine (cache / pin / mount / prefetch /
// transfers) behind the macOS client's `EngineClient` and the `cloudfs` CLI's
// local-engine ops. Architecture: DESIGN.md. Control-plane wire contract:
// CONTROL-API.md.
//
// Swift shares models and native platform integration with the macOS client.
// The production volume uses macOS kernel SMB over a loopback server.
//
// ONE PACKAGE, ONE TARGET PER MODULE (DESIGN.md §7):
//   CloudFSCore          [FROZEN] shared types + the full CONTROL-API.md contract
//                        as Codable types. Implementers depend on this read-only.
//   CloudFSCrypto        BlockCrypto       — LZ4+AES-256-GCM(+CTR-compat) pipeline
//   CloudFSCache         BlockCache        — resizable/relocatable block cache
//   CloudFSTransfer      TransferEngine    — prefetch / download / async upload
//   CloudFSGateway       GatewayClient     — HTTP client to backend/API.md
//   CloudFSMount         MountBackend      — mount-adapter protocol + no-op stub
//   CloudFSSMB           SMBLoopbackMount  — in-daemon SMB2 server (the production mount)
//   CloudFSControlPlane  ControlPlane      — UDS JSON-RPC server (the seam)
//   cloudfsd             executable        — wires every module together
//
// THE MOUNT: an in-daemon SMB2 server (CloudFSSMB) fronted by the macOS built-in
// smbfs client over loopback. Pure Swift, always compiled, no kext/cask. Protocol
// tests run headless in CI; the real mount is exercised by a CLOUDFS_LIVE_MOUNT
// gated smoke suite. See MOUNT.md.

import PackageDescription

let package = Package(
    name: "cloudfsd",
    platforms: [
        // Supported deployment baseline for the native app and loopback SMB engine.
        .macOS(.v14)
    ],
    products: [
        .executable(name: "cloudfsd", targets: ["cloudfsd"]),
        .library(name: "CloudFSCore", targets: ["CloudFSCore"]),
        .library(name: "CloudFSCrypto", targets: ["CloudFSCrypto"]),
        .library(name: "CloudFSCache", targets: ["CloudFSCache"]),
        .library(name: "CloudFSTransfer", targets: ["CloudFSTransfer"]),
        .library(name: "CloudFSGateway", targets: ["CloudFSGateway"]),
        .library(name: "CloudFSMount", targets: ["CloudFSMount"]),
        .library(name: "CloudFSSMB", targets: ["CloudFSSMB"]),
        .library(name: "CloudFSControlPlane", targets: ["CloudFSControlPlane"])
    ],
    targets: [
        // ---- FROZEN: shared types + control-plane contract ----
        .target(
            name: "CloudFSCore"
        ),

        // ---- modules: each owns its protocol + a stub conformance ----
        .target(
            name: "CloudFSCrypto",
            dependencies: ["CloudFSCore"]
        ),
        .target(
            name: "CloudFSCache",
            dependencies: ["CloudFSCore"]
        ),
        .target(
            name: "CloudFSGateway",
            dependencies: ["CloudFSCore"]
        ),
        .target(
            name: "CloudFSTransfer",
            dependencies: ["CloudFSCore", "CloudFSCache", "CloudFSCrypto", "CloudFSGateway"]
        ),

        .target(
            name: "CloudFSMount",
            dependencies: ["CloudFSCore"]
        ),

        // The PRODUCTION mount: in-daemon SMB2 server + macOS built-in smbfs
        // client, loopback. Pure Swift, always compiled (no trait, no cask).
        .target(
            name: "CloudFSSMB",
            dependencies: ["CloudFSCore", "CloudFSMount"]
        ),

        .target(
            name: "CloudFSControlPlane",
            dependencies: ["CloudFSCore"]
        ),

        // ---- executable: wires everything (cloudfsd → all) ----
        .executableTarget(
            name: "cloudfsd",
            dependencies: [
                "CloudFSCore",
                "CloudFSCrypto",
                "CloudFSCache",
                "CloudFSTransfer",
                "CloudFSGateway",
                "CloudFSMount",
                "CloudFSSMB",
                "CloudFSControlPlane"
            ]
        ),

        // ---- tests: one per target so `swift test` runs ----
        .testTarget(name: "CloudFSCoreTests", dependencies: ["CloudFSCore"]),
        .testTarget(name: "CloudFSCryptoTests", dependencies: ["CloudFSCrypto"]),
        .testTarget(name: "CloudFSCacheTests", dependencies: ["CloudFSCache"]),
        .testTarget(name: "CloudFSTransferTests", dependencies: ["CloudFSTransfer"]),
        .testTarget(name: "CloudFSGatewayTests", dependencies: ["CloudFSGateway"]),
        .testTarget(name: "CloudFSMountTests", dependencies: ["CloudFSMount"]),
        .testTarget(name: "CloudFSSMBTests", dependencies: ["CloudFSSMB", "CloudFSTransfer"]),
        .testTarget(name: "CloudFSControlPlaneTests", dependencies: ["CloudFSControlPlane"]),
        .testTarget(name: "cloudfsdTests", dependencies: ["cloudfsd"])
    ]
)
