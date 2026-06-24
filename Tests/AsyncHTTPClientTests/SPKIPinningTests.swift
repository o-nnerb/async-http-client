//===----------------------------------------------------------------------===//
//
// This source file is part of the AsyncHTTPClient open source project
//
// Copyright (c) 2026 Apple Inc. and the AsyncHTTPClient project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of AsyncHTTPClient project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import Logging
import NIOCore
import NIOEmbedded
import NIOHTTP1
import NIOPosix
import NIOSSL
import NIOTLS
import XCTest

#if canImport(Network)
import Network
import NIOTransportServices
#endif

@testable import AsyncHTTPClient

class SPKIPinningTests: XCTestCase {

    // MARK: - SPKIPinningConfiguration.contains(spkiBytes:)

    func testContains_WithMatchingPin_ReturnsTrue() throws {
        let (certificate, spkiHash) = try Self.testCertificateAndSPKIHash()
        let pin = try SPKIHash(algorithm: SHA256.self, bytes: Data(spkiHash))
        let config = SPKIPinningConfiguration(
            pins: [pin],
            policy: .strict
        )

        let publicKey = try certificate.extractPublicKey()
        let spkiBytes = try publicKey.toSPKIBytes()

        XCTAssertTrue(config.contains(spkiBytes: spkiBytes))
    }

    func testContains_WithMismatchedPin_ReturnsFalse() throws {
        let (certificate, _) = try Self.testCertificateAndSPKIHash()
        let mismatchedPin = try SPKIHash(algorithm: SHA256.self, base64: "9uO07DlRgCzpXEaC2+ZiqB0VFcjdn43d6h+U2lUHORo=")
        let config = SPKIPinningConfiguration(
            pins: [mismatchedPin],
            policy: .strict
        )

        let publicKey = try certificate.extractPublicKey()
        let spkiBytes = try publicKey.toSPKIBytes()

        XCTAssertFalse(config.contains(spkiBytes: spkiBytes))
    }

    func testContains_WithEmptyInput_ReturnsFalse() throws {
        let pin = try SPKIHash(algorithm: SHA256.self, base64: "9uO07DlRgCzpXEaC2+ZiqB0VFcjdn43d6h+U2lUHORo=")
        let config = SPKIPinningConfiguration(
            pins: [pin],
            policy: .strict
        )

        XCTAssertFalse(config.contains(spkiBytes: []))
    }

    // MARK: - SPKIPinningHandler.validatePinning(for:)

    func testValidatePinning_WithValidPin_InStrictMode_ReturnsAccepted() throws {
        let (certificate, spkiHash) = try Self.testCertificateAndSPKIHash()
        let pin = try SPKIHash(algorithm: SHA256.self, bytes: Data(spkiHash))
        let config = SPKIPinningConfiguration(
            pins: [pin],
            policy: .strict
        )
        let handler = try makeHandler(config: config)

        let result = handler.validatePinning(for: .success(certificate))

        if case .accepted = result {
            return
        }

        XCTFail("Expected validation to succeed")
    }

    func testValidatePinning_WithValidPin_InAuditMode_ReturnsAccepted() throws {
        let (certificate, spkiHash) = try Self.testCertificateAndSPKIHash()
        let pin = try SPKIHash(algorithm: SHA256.self, bytes: Data(spkiHash))
        let config = SPKIPinningConfiguration(
            pins: [pin],
            policy: .audit
        )
        let handler = try makeHandler(config: config)

        let result = handler.validatePinning(for: .success(certificate))

        if case .accepted = result {
            return
        }

        XCTFail("Expected validation to succeed, got \(result)")
    }

    func testValidatePinning_WithMismatchedPin_InStrictMode_ReturnsRejected() throws {
        let (certificate, _) = try Self.testCertificateAndSPKIHash()
        let mismatchedPin = try SPKIHash(algorithm: SHA256.self, base64: "9uO07DlRgCzpXEaC2+ZiqB0VFcjdn43d6h+U2lUHORo=")
        let config = SPKIPinningConfiguration(
            pins: [mismatchedPin],
            policy: .strict
        )
        let handler = try makeHandler(config: config)

        let result = handler.validatePinning(for: .success(certificate))

        guard case .rejected(let error) = result else {
            XCTFail("Expected .rejected, got \(result)")
            return
        }

        if case .pinMismatch = error as? SPKIPinningHandlerError {
            return
        }

        XCTFail("Expected .pinMismatch, got \(error)")
    }

    func testValidatePinning_WithMismatchedPin_InAuditMode_ReturnsAuditWarning() throws {
        let (certificate, _) = try Self.testCertificateAndSPKIHash()
        let mismatchedPin = try SPKIHash(algorithm: SHA256.self, base64: "9uO07DlRgCzpXEaC2+ZiqB0VFcjdn43d6h+U2lUHORo=")
        let config = SPKIPinningConfiguration(
            pins: [mismatchedPin],
            policy: .audit
        )
        let handler = try makeHandler(config: config)

        let result = handler.validatePinning(for: .success(certificate))

        guard case .auditWarning(let error) = result else {
            XCTFail("Expected .auditWarning, got \(result)")
            return
        }

        if case .pinMismatch = error as? SPKIPinningHandlerError {
            return
        }

        XCTFail("Expected .pinMismatch, got \(error)")
    }

    func testValidatePinning_WithNilCertificate_InStrictMode_ReturnsRejected() throws {
        let pin = try SPKIHash(algorithm: SHA256.self, base64: "9uO07DlRgCzpXEaC2+ZiqB0VFcjdn43d6h+U2lUHORo=")
        let config = SPKIPinningConfiguration(
            pins: [pin],
            policy: .strict
        )
        let handler = try makeHandler(config: config)

        let result = handler.validatePinning(for: .success(nil))

        guard case .rejected(let error) = result else {
            XCTFail("Expected .rejected, got \(result)")
            return
        }

        if case .emptyCertificateChain = error as? SPKIPinningHandlerError {
            return
        }

        XCTFail("Expected .emptyCertificateChain, got \(error)")
    }

    func testValidatePinning_WithNilCertificate_InAuditMode_ReturnsAuditWarning() throws {
        let pin = try SPKIHash(algorithm: SHA256.self, base64: "9uO07DlRgCzpXEaC2+ZiqB0VFcjdn43d6h+U2lUHORo=")
        let config = SPKIPinningConfiguration(
            pins: [pin],
            policy: .audit
        )
        let handler = try makeHandler(config: config)

        let result = handler.validatePinning(for: .success(nil))

        guard case .auditWarning(let error) = result else {
            XCTFail("Expected .auditWarning, got \(result)")
            return
        }

        if case .emptyCertificateChain = error as? SPKIPinningHandlerError {
            return
        }

        XCTFail("Expected .emptyCertificateChain, got \(error)")
    }

    func testValidatePinning_WithExtractionFailure_InStrictMode_ReturnsRejected() throws {
        let pin = try SPKIHash(algorithm: SHA256.self, base64: "9uO07DlRgCzpXEaC2+ZiqB0VFcjdn43d6h+U2lUHORo=")
        let config = SPKIPinningConfiguration(
            pins: [pin],
            policy: .strict
        )
        let handler = try makeHandler(config: config)
        let extractionError = NSError(domain: "TestError", code: 1, userInfo: nil)

        let result = handler.validatePinning(for: .failure(extractionError))

        guard case .rejected(let error) = result else {
            XCTFail("Expected .rejected, got \(result)")
            return
        }
        XCTAssertTrue((error as? SPKIPinningHandlerError)?.description.contains("SSL handler not found: ") == true)
    }

    func testValidatePinning_WithExtractionFailure_InAuditMode_ReturnsAuditWarning() throws {
        let pin = try SPKIHash(algorithm: SHA256.self, base64: "9uO07DlRgCzpXEaC2+ZiqB0VFcjdn43d6h+U2lUHORo=")
        let config = SPKIPinningConfiguration(
            pins: [pin],
            policy: .audit
        )
        let handler = try makeHandler(config: config)
        let extractionError = NSError(domain: "TestError", code: 1, userInfo: nil)

        let result = handler.validatePinning(for: .failure(extractionError))

        guard case .auditWarning(let error) = result else {
            XCTFail("Expected .auditWarning, got \(result)")
            return
        }
        XCTAssertTrue((error as? SPKIPinningHandlerError)?.description.contains("SSL handler not found: ") == true)
    }

    // MARK: - SPKIPinningHandler.userInboundEventTriggered(...)

    func testUserInboundEventTriggered_IgnoresNonHandshakeEvents() throws {
        let config = SPKIPinningConfiguration(
            pins: [],
            policy: .strict
        )
        let handler = try makeHandler(config: config)
        let event = TLSUserEvent.shutdownCompleted

        let embedded = EmbeddedChannel(handlers: [handler])
        embedded.pipeline.fireUserInboundEventTriggered(event)
        try embedded.throwIfErrorCaught()
    }

    func testUserInboundEventTriggered_OnHandshakeInitiatesValidation() throws {
        let config = SPKIPinningConfiguration(
            pins: [],
            policy: .strict
        )
        let handler = try makeHandler(config: config)
        let event = TLSUserEvent.handshakeCompleted(negotiatedProtocol: nil)

        let embedded = EmbeddedChannel(handlers: [handler])
        embedded.pipeline.fireUserInboundEventTriggered(event)

        XCTAssertThrowsError(try embedded.throwIfErrorCaught()) {
            if let error = $0 as? HTTPClientError {
                XCTAssertTrue(error.description.contains("SSL handler not found: "))
            }
        }
    }

    // MARK: - End-to-End Tests: HTTP/2

    func testSPKIPinning_HTTP2_ValidPin_AllowsConnection() async throws {
        try await runSPKIPinningTest(
            useValidPin: true,
            policy: .strict,
            mode: .http2(tlsConfiguration: TestTLS.serverConfiguration)
        )
    }

    func testSPKIPinning_HTTP2_InvalidPin_RejectsConnection() async throws {
        try await runSPKIPinningTest(
            useValidPin: false,
            policy: .strict,
            mode: .http2(tlsConfiguration: TestTLS.serverConfiguration)
        )
    }

    func testSPKIPinning_HTTP2_ValidPin_AuditMode_AllowsConnection() async throws {
        try await runSPKIPinningTest(
            useValidPin: true,
            policy: .audit,
            mode: .http2(tlsConfiguration: TestTLS.serverConfiguration)
        )
    }

    func testSPKIPinning_HTTP2_InvalidPin_AuditMode_AllowsConnection() async throws {
        try await runSPKIPinningTest(
            useValidPin: false,
            policy: .audit,
            mode: .http2(tlsConfiguration: TestTLS.serverConfiguration)
        )
    }

    // MARK: - End-to-End Tests: HTTP/1.1

    func testSPKIPinning_HTTP1_ValidPin_AllowsConnection() async throws {
        try await runSPKIPinningTest(
            useValidPin: true,
            policy: .strict,
            mode: .http1_1(tlsConfiguration: TestTLS.serverConfiguration)
        )
    }

    func testSPKIPinning_HTTP1_InvalidPin_RejectsConnection() async throws {
        try await runSPKIPinningTest(
            useValidPin: false,
            policy: .strict,
            mode: .http1_1(tlsConfiguration: TestTLS.serverConfiguration)
        )
    }

    func testSPKIPinning_HTTP1_ValidPin_AuditMode_AllowsConnection() async throws {
        try await runSPKIPinningTest(
            useValidPin: true,
            policy: .audit,
            mode: .http1_1(tlsConfiguration: TestTLS.serverConfiguration)
        )
    }

    func testSPKIPinning_HTTP1_InvalidPin_AuditMode_AllowsConnection() async throws {
        try await runSPKIPinningTest(
            useValidPin: false,
            policy: .audit,
            mode: .http1_1(tlsConfiguration: TestTLS.serverConfiguration)
        )
    }

    // MARK: - End-to-End Tests: Network.framework

    #if canImport(Network)
    func testSPKIPinning_NetworkFramework_ThrowsUnsupportedError() async throws {
        try XCTSkipUnless(isTestingNIOTS(), "Network.framework tests disabled")

        let certificate = TestTLS.certificate
        let spkiHash = SHA256.hash(data: Data(UUID().uuidString.utf8))
        let pinBase64 = Data(spkiHash).base64EncodedString()

        let tlsConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(certificate)],
            privateKey: .privateKey(TestTLS.privateKey)
        )

        let bin = HTTPBin(.http2(tlsConfiguration: tlsConfig))
        defer { XCTAssertNoThrow(try bin.shutdown()) }

        var config = HTTPClient.Configuration().enableFastFailureModeForTesting()
        config.tlsConfiguration = TLSConfiguration.makeClientConfiguration()
        config.tlsConfiguration?.trustRoots = .certificates([certificate])
        // Network.framework não suporta .noHostnameVerification, então removemos essa linha

        config.tlsPinning = SPKIPinningConfiguration(
            pins: [try SPKIHash(algorithm: SHA256.self, base64: pinBase64)],
            policy: .strict
        )

        let eventLoopGroup = NIOTSEventLoopGroup(loopCount: 1, defaultQoS: .default)
        defer { XCTAssertNoThrow(try eventLoopGroup.syncShutdownGracefully()) }

        let localClient = HTTPClient(
            eventLoopGroupProvider: .shared(eventLoopGroup),
            configuration: config
        )
        defer { XCTAssertNoThrow(try localClient.syncShutdown()) }

        let request = HTTPClientRequest(url: "https://localhost:\(bin.port)/get")

        do {
            _ = try await localClient.execute(request, deadline: .now() + .seconds(10))
            XCTFail("Expected error but request succeeded")
        } catch let error as SPKIPinningHandlerError {
            XCTAssertEqual(error, .networkFrameworkNotSupported)
        } catch {
            XCTFail("Expected SPKIPinningHandlerError.networkFrameworkNotSupported, received: \(type(of: error))")
        }
    }
    #endif

    // MARK: - Helpers

    private func makeHandler(config: SPKIPinningConfiguration) throws -> SPKIPinningHandler {
        let logger = Logger(label: "test", factory: SwiftLogNoOpLogHandler.init)
        return SPKIPinningHandler(tlsPinning: config, logger: logger)
    }

    private static func testCertificateAndSPKIHash() throws -> (NIOSSLCertificate, SHA256Digest) {
        let certificate = TestTLS.certificate
        let publicKey = try certificate.extractPublicKey()
        let spkiBytes = try publicKey.toSPKIBytes()
        let spkiHash = SHA256.hash(data: Data(spkiBytes))
        return (certificate, spkiHash)
    }

    private func runSPKIPinningTest(
        useValidPin: Bool,
        policy: SPKIPinningPolicy,
        mode: HTTPBin<HTTPBinHandler>.Mode,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async throws {
        let bin = HTTPBin(mode)
        defer { XCTAssertNoThrow(try bin.shutdown()) }

        let pinBase64: String
        if useValidPin {
            let publicKey = try TestTLS.certificate.extractPublicKey()
            let spkiBytes = try publicKey.toSPKIBytes()
            let spkiHash = SHA256.hash(data: Data(spkiBytes))
            pinBase64 = Data(spkiHash).base64EncodedString()
        } else {
            let spkiHash = SHA256.hash(data: Data(UUID().uuidString.utf8))
            pinBase64 = Data(spkiHash).base64EncodedString()
        }

        var config = HTTPClient.Configuration().enableFastFailureModeForTesting()
        config.tlsConfiguration = TLSConfiguration.makeClientConfiguration()
        config.tlsConfiguration?.trustRoots = .certificates([TestTLS.certificate])
        config.tlsConfiguration?.certificateVerification = .noHostnameVerification
        config.httpVersion = .automatic

        config.tlsPinning = SPKIPinningConfiguration(
            pins: [try SPKIHash(algorithm: SHA256.self, base64: pinBase64)],
            policy: policy
        )

        let localClient = HTTPClient(
            eventLoopGroupProvider: .shared(MultiThreadedEventLoopGroup.singleton),
            configuration: config
        )
        defer { XCTAssertNoThrow(try localClient.syncShutdown()) }

        let request = HTTPClientRequest(url: "https://localhost:\(bin.port)/get")

        let expectedVersion: HTTPVersion = {
            switch mode {
            case .http2:
                return .http2
            case .http1_1:
                return .http1_1
            case .refuse:
                return .http1_1
            }
        }()

        if useValidPin || policy == .audit {
            do {
                let response = try await localClient.execute(request, deadline: .now() + .seconds(10))
                XCTAssertEqual(response.status, .ok, file: file, line: line)
                XCTAssertEqual(response.version, expectedVersion, file: file, line: line)
            } catch {
                XCTFail("Unexpected error: \(error)", file: file, line: line)
            }
        } else {
            do {
                _ = try await localClient.execute(request, deadline: .now() + .seconds(10))
                XCTFail("Expected error but request succeeded", file: file, line: line)
            } catch let error as HTTPClientError {
                XCTAssertTrue(
                    error.description.contains("pinning") || error.description.contains("SPKI"),
                    "Unexpected error: \(error.description)",
                    file: file,
                    line: line
                )
            } catch {
                XCTFail("Expecting HTTPClientError, received: \(type(of: error))", file: file, line: line)
            }
        }
    }
}
