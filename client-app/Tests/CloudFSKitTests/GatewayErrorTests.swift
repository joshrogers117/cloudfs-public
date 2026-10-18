// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// Regression for the "…GatewayError error 0." class (auth-spec §0.2 #3 / §6.6):
// GatewayError now conforms to LocalizedError, so `error.localizedDescription`
// — what AppModel surfaces to the UI — is the human message, never Foundation's
// domain+code fallback.

@Suite struct GatewayErrorTests {

    private let allCases: [HttpGatewayClient.GatewayError] = [
        .badURL,
        .http(status: 401, code: "invalid_refresh", reason: nil),
        .http(status: 403, code: "cross_tenant", reason: "org mismatch"),
        .decoding("Filespace: missing id"),
        .transport("The Internet connection appears to be offline."),
        .unsupported("pin is a cloudfsd cache policy"),
    ]

    @Test func localizedDescriptionEqualsDescriptionForEveryCase() {
        for error in allCases {
            #expect(error.localizedDescription == error.description)
        }
    }

    @Test func errorZeroIsUnproducible() {
        for error in allCases {
            let shown = (error as Error).localizedDescription
            #expect(!shown.isEmpty)
            #expect(!shown.contains("error 0"))
            #expect(!shown.contains("GatewayError"))   // no type-name fallback leaks
        }
    }

    @Test func httpCaseCarriesStatusCodeAndReason() {
        let error = HttpGatewayClient.GatewayError.http(
            status: 401, code: "device_expired", reason: "rotate failed")
        #expect(error.localizedDescription == "HTTP 401 device_expired: rotate failed")
    }
}
