// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// MARK: - DeviceAuthAPI — the auth-spec §2 endpoints the Mac app calls
//
//   GET  /v1/auth/config/public          (reachability probe + webBaseUrl)
//   POST /v1/auth/device/token           { code, codeVerifier } → device session
//   POST /v1/auth/device/refresh         { refreshToken } → rotated pair
//   POST /v1/auth/device/daemon-token    Bearer access JWS → 30-day daemon token
//
// Errors use the gateway's `{ error, reason }` envelope and surface as
// `HttpGatewayClient.GatewayError` (which is LocalizedError — never "error 0").
// The protocol seam exists so AuthSessionManager is testable with an in-memory
// fake; the URLSession implementation is itself testable via StubURLProtocol.

// MARK: Wire shapes (spec §2.3/§2.4/§2.7/§2.8)

public struct PublicAuthConfig: Decodable, Sendable, Equatable {
    public let mode: String
    public let oidcEnabled: Bool?
    public let providerLabel: String?
    public let webBaseUrl: String?
    public let productName: String?

    public init(mode: String, oidcEnabled: Bool? = nil, providerLabel: String? = nil,
                webBaseUrl: String? = nil, productName: String? = nil) {
        self.mode = mode; self.oidcEnabled = oidcEnabled
        self.providerLabel = providerLabel
        self.webBaseUrl = webBaseUrl; self.productName = productName
    }
}

public struct DeviceTokenResponse: Decodable, Sendable, Equatable {
    public struct Account: Decodable, Sendable, Equatable {
        public let email: String?
        public let displayName: String?
        public let role: String?
        public init(email: String?, displayName: String? = nil, role: String? = nil) {
            self.email = email; self.displayName = displayName; self.role = role
        }
    }
    public struct Device: Decodable, Sendable, Equatable {
        public let id: String?
        public let name: String?
        public init(id: String?, name: String? = nil) { self.id = id; self.name = name }
    }
    public let refreshToken: String
    public let accessToken: String
    public let accessTtlSeconds: Double
    public let orgId: String
    public let orgName: String?
    public let account: Account?
    public let device: Device?

    public init(refreshToken: String, accessToken: String, accessTtlSeconds: Double,
                orgId: String, orgName: String? = nil,
                account: Account? = nil, device: Device? = nil) {
        self.refreshToken = refreshToken; self.accessToken = accessToken
        self.accessTtlSeconds = accessTtlSeconds; self.orgId = orgId
        self.orgName = orgName; self.account = account; self.device = device
    }
}

public struct DeviceRefreshResponse: Decodable, Sendable, Equatable {
    public let refreshToken: String
    public let accessToken: String
    public let accessTtlSeconds: Double
    public init(refreshToken: String, accessToken: String, accessTtlSeconds: Double) {
        self.refreshToken = refreshToken; self.accessToken = accessToken
        self.accessTtlSeconds = accessTtlSeconds
    }
}

public struct DaemonTokenResponse: Decodable, Sendable, Equatable {
    public let id: String?
    public let token: String
    public let expiresAt: Double      // epoch MILLISECONDS (gateway convention)
    public let scopes: [String]?
    public init(id: String?, token: String, expiresAt: Double, scopes: [String]? = nil) {
        self.id = id; self.token = token; self.expiresAt = expiresAt; self.scopes = scopes
    }
    public var expiryDate: Date { Date(timeIntervalSince1970: expiresAt / 1000.0) }
}

// MARK: The seam

public protocol DeviceAuthAPIProtocol: Sendable {
    func publicConfig() async throws -> PublicAuthConfig
    func exchange(code: String, codeVerifier: String) async throws -> DeviceTokenResponse
    func refresh(refreshToken: String) async throws -> DeviceRefreshResponse
    func mintDaemonToken(accessToken: String) async throws -> DaemonTokenResponse
}

// MARK: URLSession implementation

public struct DeviceAuthAPI: DeviceAuthAPIProtocol, Sendable {
    public let baseURL: String
    private let session: URLSession

    public init(baseURL: String, session: URLSession = .shared) {
        self.baseURL = baseURL.trimmingCharacters(in: .whitespacesAndNewlines)
        self.session = session
    }

    public func publicConfig() async throws -> PublicAuthConfig {
        try await request(PublicAuthConfig.self, "GET", "/v1/auth/config/public")
    }

    public func exchange(code: String, codeVerifier: String) async throws -> DeviceTokenResponse {
        try await request(DeviceTokenResponse.self, "POST", "/v1/auth/device/token",
                          body: ["code": code, "codeVerifier": codeVerifier])
    }

    public func refresh(refreshToken: String) async throws -> DeviceRefreshResponse {
        try await request(DeviceRefreshResponse.self, "POST", "/v1/auth/device/refresh",
                          body: ["refreshToken": refreshToken])
    }

    public func mintDaemonToken(accessToken: String) async throws -> DaemonTokenResponse {
        try await request(DaemonTokenResponse.self, "POST", "/v1/auth/device/daemon-token",
                          body: [:], bearer: accessToken)
    }

    // MARK: plumbing (mirrors HttpGatewayClient's request/error handling)

    private struct ErrorEnvelope: Decodable { let error: String?; let reason: String? }

    private func request<T: Decodable>(
        _ type: T.Type, _ method: String, _ path: String,
        body: [String: String]? = nil, bearer: String? = nil
    ) async throws -> T {
        guard var comps = URLComponents(string: baseURL),
              comps.scheme != nil, let host = comps.host, !host.isEmpty
        else { throw HttpGatewayClient.GatewayError.badURL }
        let basePath = comps.path.hasSuffix("/") ? String(comps.path.dropLast()) : comps.path
        comps.path = basePath + path
        guard let url = comps.url else { throw HttpGatewayClient.GatewayError.badURL }

        var req = URLRequest(url: url)
        req.httpMethod = method
        if let bearer {
            req.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization")
        }
        if let body {
            req.setValue("application/json", forHTTPHeaderField: "content-type")
            req.httpBody = try? JSONEncoder().encode(body)
        }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: req)
        } catch {
            throw HttpGatewayClient.GatewayError.transport(error.localizedDescription)
        }
        guard let http = response as? HTTPURLResponse else {
            throw HttpGatewayClient.GatewayError.transport("non-HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            let env = try? JSONDecoder().decode(ErrorEnvelope.self, from: data)
            throw HttpGatewayClient.GatewayError.http(
                status: http.statusCode,
                code: env?.error ?? "error",
                reason: env?.reason)
        }
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw HttpGatewayClient.GatewayError.decoding("\(type): \(error)")
        }
    }
}
