import XCTest
import Foundation
@testable import GPGPCore

final class FailureHandlingTests: XCTestCase {
    func testFailedOrEmptyReplyNeverBecomesOutgoingContent() throws {
        let partial = Data("partial output".utf8)
        XCTAssertThrowsError(try SecuredMessageReply.requireContent(partial, error: "Signing was cancelled."))
        XCTAssertThrowsError(try SecuredMessageReply.requireContent(partial, error: ""))
        XCTAssertThrowsError(try SecuredMessageReply.requireContent(nil, error: nil))
        XCTAssertThrowsError(try SecuredMessageReply.requireContent(Data(), error: nil))
        XCTAssertEqual(try SecuredMessageReply.requireContent(partial, error: nil), partial)
    }

    func testEngineFailureAndLaunchFailureReturnNoOutgoingMessage() {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("gpgp-failure-" + UUID().uuidString)
        let raw = Data("From: Test <test@example.invalid>\r\nTo: test@example.invalid\r\nContent-Type: text/plain\r\n\r\nMust not be sent unprotected.\r\n".utf8)
        for executable in ["/usr/bin/false", "/nonexistent-gpgp-test-engine"] {
            let signed = PersonalMessageSigner.sign(raw, executable: executable, keyring: folder, fingerprint: String(repeating: "A", count: 40))
            XCTAssertNil(signed.0); XCTAssertNotNil(signed.1)
            let encrypted = PersonalMessageEncryptor.encode(raw, executable: executable, keyring: folder, fingerprint: String(repeating: "A", count: 40), sign: false)
            XCTAssertNil(encrypted.0); XCTAssertNotNil(encrypted.1)
        }
    }

    func testBundledProbeSeparatesWarningsFromJSON() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("gpgp-probe-test-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: folder) }
        let helper = folder.appendingPathComponent("helper")
        let script = #"""
        #!/bin/sh
        printf 'A simulated runtime warning\n' >&2
        printf '{"protocolVersion":1,"reply":"pong","nonce":"%s"}\n' "$2"
        """#
        try Data(script.utf8).write(to: helper)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: helper.path)
        let result = BridgeProbe.run(executable: helper)
        XCTAssertTrue(result.hasPrefix("PASS:"), result)
        XCTAssertTrue(result.contains("simulated runtime warning"))
        try Data("#!/bin/sh\nprintf 'not-json'\n".utf8).write(to: helper)
        let malformed = BridgeProbe.run(executable: helper)
        XCTAssertTrue(malformed.contains("invalid diagnostic reply"), malformed)
        XCTAssertFalse(malformed.hasPrefix("PASS:"))
    }

    func testUnavailableHelperCompletesOnceWithActionableError() {
        let completed = expectation(description: "helper failure")
        completed.assertForOverFulfill = true
        let request = SecurityBridgeRequest<String>(seconds: 0.15, serviceName: "com.JimKelley.GPGP.missing-test-" + UUID().uuidString) { result in
            switch result {
            case .success: XCTFail("An unavailable helper cannot return a successful reply.")
            case .failure(let error): XCTAssertTrue(error.localizedDescription.contains("GPGP"))
            }
            completed.fulfill()
        }
        request.start { proxy, done in
            proxy.ping(UUID().uuidString) { done(.success($0)) }
        }
        wait(for: [completed], timeout: 2)
        // Let the competing timeout/invalidation paths run. A second callback
        // would over-fulfil the expectation and fail this test.
        let drained = expectation(description: "drain competing completions")
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) { drained.fulfill() }
        wait(for: [drained], timeout: 1)
    }
}
