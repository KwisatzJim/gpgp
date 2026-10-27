import XCTest
import Foundation
@testable import GPGPCore

final class IndependentImplementationTests: XCTestCase {
    func testOpenPGPJSExchange() throws {
        guard let location = ProcessInfo.processInfo.environment["GPGP_INTEROP_DIR"] else {
            throw XCTSkip("Run npm test in Scripts/Interop for independent implementation fixtures.")
        }
        let folder = URL(fileURLWithPath: location)
        let gpg = try XCTUnwrap(KeyringCatalog.executable)
        let home = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("gpgp-interop-keys-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer {
            let gpgconf = URL(fileURLWithPath: gpg).deletingLastPathComponent().appendingPathComponent("gpgconf").path
            _ = try? KeyringCatalog.command(gpgconf, ["--homedir", home.path, "--kill", "gpg-agent"])
            try? FileManager.default.removeItem(at: home)
        }
        let imported = try KeyringCatalog.command(gpg, ["--no-options", "--homedir", home.path, "--batch", "--import", folder.appendingPathComponent("private.asc").path])
        guard imported.status == 0 else { return XCTFail("Fixture import failed: " + imported.error) }
        let fingerprint = try String(contentsOf: folder.appendingPathComponent("fingerprint"), encoding: .utf8)
        let expected = try Data(contentsOf: folder.appendingPathComponent("content.mime"))
        let incomingSigned = try Data(contentsOf: folder.appendingPathComponent("incoming-signed.eml"))
        let checked = IncomingSignatureVerifier.verify(incomingSigned, executable: gpg, keyring: home)
        XCTAssertEqual(checked.1, fingerprint); XCTAssertNil(checked.2)
        XCTAssertTrue(try XCTUnwrap(checked.0).suffix(expected.count).elementsEqual(expected))
        let incomingEncrypted = try Data(contentsOf: folder.appendingPathComponent("incoming-encrypted.eml"))
        let decrypted = IncomingMessageDecryptor.decrypt(incomingEncrypted, executable: gpg, keyring: home)
        XCTAssertNil(decrypted.2); XCTAssertNil(decrypted.3)
        XCTAssertTrue(try XCTUnwrap(decrypted.0).suffix(expected.count).elementsEqual(expected))
        let raw = Data("From: Interop Sender <interop@example.invalid>\r\nTo: interop@example.invalid\r\nSubject: GPGP interop reply\r\n".utf8) + expected
        let signed = PersonalMessageSigner.sign(raw, executable: gpg, keyring: home, fingerprint: fingerprint)
        try XCTUnwrap(signed.0, signed.1 ?? "No signed output").write(to: folder.appendingPathComponent("outgoing-signed.eml"))
        let encrypted = PersonalMessageEncryptor.encode(raw, executable: gpg, keyring: home, fingerprint: fingerprint, sign: false)
        try XCTUnwrap(encrypted.0, encrypted.1 ?? "No encrypted output").write(to: folder.appendingPathComponent("outgoing-encrypted.eml"))
    }
}
