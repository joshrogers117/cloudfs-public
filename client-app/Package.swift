// swift-tools-version: 6.0
// SPDX-License-Identifier: AGPL-3.0-or-later
// Native macOS control app and testable gateway/daemon client library.
// The default app uses browser sign-in and the embedded SMB streaming daemon.
// CLOUDFS_DEMO=1 explicitly selects offline sample data for visual development.
// Build the distributable host, framework and Finder extension with
// scripts/make-app-smb.sh; SwiftPM remains useful for development and tests.

import PackageDescription

let package = Package(
    name: "CloudFSClient",
    platforms: [
        .macOS(.v14) // SwiftUI MenuBarExtra (Window scene) + modern navigation
    ],
    products: [
        .executable(name: "CloudFSApp", targets: ["CloudFSApp"]),
        .library(name: "CloudFSKit", targets: ["CloudFSKit"])
    ],
    targets: [
        .target(
            name: "CloudFSKit"
        ),
        .executableTarget(
            name: "CloudFSApp",
            dependencies: ["CloudFSKit"]
        ),
        .testTarget(
            name: "CloudFSKitTests",
            dependencies: ["CloudFSKit"]
        )
    ]
)
