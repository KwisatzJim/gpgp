import XCTest
import Foundation
import CryptoKit
@testable import GPGPCore

final class FormatAndPolicyTests: XCTestCase {
    func testRuntimeDiscoveryForAppAndBackgroundHelper() throws {
        let parent = FileManager.default.temporaryDirectory.appendingPathComponent("GPGP runtime layout " + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: parent) }
        let app = parent.appendingPathComponent("GPGP Test.app")
        let root = app.appendingPathComponent("Contents/Resources/GnuPG")
        try FileManager.default.createDirectory(at: root.appendingPathComponent("bin"), withIntermediateDirectories: true)
        XCTAssertNil(GnuPGRuntime.bundledRoot(startingAt: app.appendingPathComponent("Contents/MacOS/GPGPBridge")))
        try Data("{}".utf8).write(to: root.appendingPathComponent("runtime-manifest.json"))
        XCTAssertEqual(GnuPGRuntime.bundledRoot(startingAt: app.appendingPathComponent("Contents/MacOS/GPGP"))?.path, root.path)
        XCTAssertEqual(GnuPGRuntime.bundledRoot(startingAt: app.appendingPathComponent("Contents/MacOS/GPGPBridge"))?.path, root.path)
        XCTAssertTrue(GnuPGRuntime.isBundled(root.appendingPathComponent("bin/gpg").path))
    }

    func testLineEndingsPreserveBytesAndFinalNewline() {
        XCTAssertEqual(CanonicalMIME.lineEndings(Data("a\nb\r\nc".utf8)), Data("a\r\nb\r\nc".utf8))
        XCTAssertEqual(CanonicalMIME.lineEndings(Data("a\n".utf8)), Data("a\r\n".utf8))
        XCTAssertEqual(MailKitEncryptionTransport.decoded(Data("a\r\nb\r\n".utf8)), Data("a\nb\n".utf8))
        XCTAssertEqual(MailKitEncryptionTransport.decoded(Data([0, 13, 10, 255])), Data([0, 10, 255]))
    }

    func testMalformedEncryptedMessagesAreNotAccepted() {
        for input in ["not MIME", "Content-Type: multipart/encrypted; boundary=x\r\n\r\n",
                      "Content-Type: multipart/encrypted; boundary=x\r\nContent-Type: application/octet-stream\r\n\r\n"] {
            XCTAssertThrowsError(try IncomingEncryptedMail.parse(Data(input.utf8)))
            XCTAssertThrowsError(try MailKitEncryptionTransport.prepare(Data(input.utf8)))
            XCTAssertThrowsError(try MailKitEncryptionTransport.prepare(Data(input.utf8), encrypted: false))
        }
    }

    func testRecipientPolicyRequiresPinnedUsableKey() throws {
        let own = GPGPKey(fingerprint: String(repeating: "A", count: 40), identities: [Fixture.identity],
            emails: [Fixture.email], canSign: true, canEncrypt: true, usable: true, expires: nil, secret: true)
        let other = GPGPKey(fingerprint: String(repeating: "B", count: 40), identities: ["Bob <bob@example.invalid>"],
            emails: ["bob@example.invalid"], canSign: true, canEncrypt: true, usable: true, expires: nil, secret: false)
        let approval = RecipientApproval(email: "bob@example.invalid", fingerprint: other.fingerprint, approvedAt: Date())
        XCTAssertThrowsError(try PersonalMessageEncryptor.resolve(recipients: ["bob@example.invalid"], ownFingerprint: own.fingerprint, ownEmail: Fixture.email, keys: [own, other], approvals: []))
        XCTAssertEqual(try PersonalMessageEncryptor.resolve(recipients: ["bob@example.invalid"], ownFingerprint: own.fingerprint, ownEmail: Fixture.email, keys: [own, other], approvals: [approval]), [own.fingerprint, other.fingerprint])
        XCTAssertThrowsError(try PersonalMessageEncryptor.resolve(recipients: ["bob@example.invalid"], ownFingerprint: own.fingerprint, ownEmail: Fixture.email, keys: [own], approvals: [approval]))
        let expired = GPGPKey(fingerprint: other.fingerprint, identities: other.identities, emails: other.emails,
            canSign: true, canEncrypt: true, usable: false, expires: .distantPast, secret: false)
        XCTAssertThrowsError(try PersonalMessageEncryptor.resolve(recipients: ["bob@example.invalid"], ownFingerprint: own.fingerprint, ownEmail: Fixture.email, keys: [own, expired], approvals: [approval]))
        XCTAssertThrowsError(try PersonalMessageEncryptor.resolve(recipients: [], ownFingerprint: own.fingerprint, ownEmail: Fixture.email, keys: [own], approvals: []))
    }

    func testCatalogDecodesIdentityEscapesAndRejectsExpiredKeys() {
        let fpr = String(repeating: "A", count: 40)
        var primary = Array(repeating: "", count: 17)
        primary[0] = "pub"; primary[1] = "u"; primary[6] = "1"; primary[11] = "scESC"
        let rows = [primary.joined(separator: ":"), "fpr:::::::::" + fpr + ":", "uid:u::::::::Test \\x53ender <sender@example.invalid>:"]
        let key = KeyringCatalog.parse(rows.joined(separator: "\n")).first
        XCTAssertEqual(key?.title, Fixture.identity)
        XCTAssertEqual(key?.emails, [Fixture.email])
        XCTAssertEqual(key?.usable, false)
    }

    func testSenderSelectionPinsFingerprintAndDoesNotGuess() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("gpgp-selection-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: folder) }
        let file = folder.appendingPathComponent("sender.json")
        XCTAssertNil(try SenderIdentity.load(at: file))
        let first = GPGPKey(fingerprint: String(repeating: "A", count: 40), identities: [Fixture.identity], emails: [Fixture.email], canSign: true, canEncrypt: true, usable: true, expires: nil, secret: true)
        let second = GPGPKey(fingerprint: String(repeating: "B", count: 40), identities: [Fixture.identity], emails: [Fixture.email], canSign: true, canEncrypt: true, usable: true, expires: nil, secret: true)
        let selected = SenderIdentity(email: Fixture.email, fingerprint: second.fingerprint)
        try selected.save(keys: [first, second], at: file)
        XCTAssertEqual(try SenderIdentity.load(at: file), selected)
        XCTAssertEqual(try selected.validated(in: [first, second]).fingerprint, second.fingerprint)
        XCTAssertThrowsError(try selected.validated(in: [first]))
        XCTAssertThrowsError(try SenderIdentity(email: "other@example.invalid", fingerprint: second.fingerprint).validated(in: [second]))
        let publicOnly = GPGPKey(fingerprint: second.fingerprint, identities: second.identities, emails: second.emails, canSign: true, canEncrypt: true, usable: true, expires: nil, secret: false)
        XCTAssertThrowsError(try selected.validated(in: [publicOnly]))
        try Data("corrupt".utf8).write(to: file)
        XCTAssertThrowsError(try selected.save(keys: [second], at: file))
        XCTAssertEqual(try String(contentsOf: file, encoding: .utf8), "corrupt")
    }

    func testApprovalPersistenceDoesNotSilentlyReplaceCorruptPolicy() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: folder) }
        let file = folder.appendingPathComponent("recipients.json")
        try KeyringCatalog.approve(email: "bob@example.invalid", fingerprint: String(repeating: "A", count: 40), at: file)
        XCTAssertEqual(try KeyringCatalog.approvals(at: file).count, 1)
        try KeyringCatalog.revoke(email: "bob@example.invalid", at: file)
        XCTAssertTrue(try KeyringCatalog.approvals(at: file).isEmpty)
        try Data("corrupt".utf8).write(to: file)
        XCTAssertThrowsError(try KeyringCatalog.approve(email: "bob@example.invalid", fingerprint: String(repeating: "B", count: 40), at: file))
        XCTAssertEqual(try String(contentsOf: file, encoding: .utf8), "corrupt")
    }
}

final class CryptoWorkflowTests: XCTestCase {
    private static var fixture: Fixture?
    private var fixture: Fixture { Self.fixture! }

    override func setUpWithError() throws {
        guard ProcessInfo.processInfo.environment["GPGP_TEST_GPG"] != nil || KeyringCatalog.executable != nil else { throw XCTSkip("Install GnuPG to run crypto tests.") }
        if Self.fixture == nil { Self.fixture = try Fixture() }
    }
    override class func tearDown() {
        fixture?.close()
        fixture = nil
        super.tearDown()
    }

    func testSelectedSenderLookupChecksAddressAndExactKey() throws {
        let selected = SenderIdentity(email: Fixture.email, fingerprint: fixture.own)
        let good = PersonalSigningIdentity.lookup(sender: Fixture.email.uppercased(), selected: selected, executable: fixture.gpg, keyring: fixture.home)
        XCTAssertEqual(good.0, fixture.own); XCTAssertNil(good.1)
        let wrongAddress = PersonalSigningIdentity.lookup(sender: "bob@example.invalid", selected: selected, executable: fixture.gpg, keyring: fixture.home)
        XCTAssertNil(wrongAddress.0); XCTAssertNotNil(wrongAddress.1)
        let wrongKey = PersonalSigningIdentity.lookup(sender: Fixture.email, selected: SenderIdentity(email: Fixture.email, fingerprint: fixture.bob), executable: fixture.gpg, keyring: fixture.home)
        XCTAssertNil(wrongKey.0); XCTAssertNotNil(wrongKey.1)
    }

    func testSigningAndTamperRejection() throws {
        let signed = PersonalMessageSigner.sign(fixture.message, executable: fixture.gpg, keyring: fixture.home, fingerprint: fixture.own)
        let raw = try XCTUnwrap(signed.0, signed.1 ?? "No signed data")
        let native = try MailKitEncryptionTransport.prepare(raw, encrypted: false)
        XCTAssertFalse(String(decoding: native, as: UTF8.self).contains("\r\n"))
        XCTAssertEqual(CanonicalMIME.lineEndings(native), raw)
        let verified = IncomingSignatureVerifier.verify(native, executable: fixture.gpg, keyring: fixture.home)
        XCTAssertEqual(verified.1, fixture.own); XCTAssertNil(verified.2)
        let wrongDigest = Data(String(decoding: raw, as: UTF8.self).replacingOccurrences(of: "micalg=pgp-sha256", with: "micalg=pgp-sha512").utf8)
        let mismatched = IncomingSignatureVerifier.verify(wrongDigest, executable: fixture.gpg, keyring: fixture.home)
        XCTAssertNil(mismatched.1); XCTAssertNotNil(mismatched.2)
        let text = String(decoding: raw, as: UTF8.self)
        let changed = Data(text.replacingOccurrences(of: "charset=utf-8", with: "charset=us-ascii").utf8)
        let rejected = IncomingSignatureVerifier.verify(changed, executable: fixture.gpg, keyring: fixture.home)
        XCTAssertNil(rejected.1); XCTAssertNotNil(rejected.2)
    }

    func testEncryptDecryptAndMailNativeDisplayBytes() throws {
        for sign in [false, true] {
            let result = PersonalMessageEncryptor.encode(fixture.message, executable: fixture.gpg, keyring: fixture.home, fingerprint: fixture.own, sign: sign)
            let raw = try XCTUnwrap(result.0, result.1 ?? "No ciphertext")
            let native = try MailKitEncryptionTransport.prepare(raw)
            XCTAssertEqual(CanonicalMIME.lineEndings(native), raw)
            let decoded = IncomingMessageDecryptor.decrypt(native, executable: fixture.gpg, keyring: fixture.home)
            XCTAssertNotNil(decoded.0, decoded.3 ?? "No plaintext")
            XCTAssertNil(decoded.2); XCTAssertNil(decoded.3)
            XCTAssertEqual(decoded.1, sign ? fixture.own : nil)
            let displayed = MailKitEncryptionTransport.decoded(try XCTUnwrap(decoded.0))
            XCTAssertTrue(String(decoding: displayed, as: UTF8.self).contains("\n\n"))
            XCTAssertFalse(String(decoding: displayed, as: UTF8.self).contains("\r\n"))
        }
    }

    func testHTMLAndAttachmentRoundTripsPreserveMIME() throws {
        let binary = Data((0...255).map { UInt8($0) })
        let attachment = binary.base64EncodedString()
        let bodies = [
            "Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n<p>HTML café 🔐</p>\r\n",
            "Content-Type: multipart/mixed; boundary=fixture_parts\r\n\r\n--fixture_parts\r\nContent-Type: text/plain\r\n\r\nAttachment fixture\r\n--fixture_parts\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=sample.bin\r\nContent-Transfer-Encoding: base64\r\n\r\n" + attachment + "\r\n--fixture_parts--\r\n"
        ]
        for body in bodies {
            let raw = Data(("From: " + Fixture.identity + "\r\nTo: bob@example.invalid\r\nSubject: MIME fixture\r\n" + body).utf8)
            let expected = try OutgoingSignedMail.prepare(raw).content
            let signed = PersonalMessageSigner.sign(raw, executable: fixture.gpg, keyring: fixture.home, fingerprint: fixture.own)
            let verified = IncomingSignatureVerifier.verify(try XCTUnwrap(signed.0, signed.1 ?? ""), executable: fixture.gpg, keyring: fixture.home)
            XCTAssertEqual(verified.1, fixture.own); XCTAssertNil(verified.2)
            XCTAssertTrue(try XCTUnwrap(verified.0).suffix(expected.count).elementsEqual(expected))
            for sign in [false, true] {
                let encrypted = PersonalMessageEncryptor.encode(raw, executable: fixture.gpg, keyring: fixture.home, fingerprint: fixture.own, sign: sign, recipients: [fixture.own, fixture.bob])
                let decrypted = IncomingMessageDecryptor.decrypt(try XCTUnwrap(encrypted.0, encrypted.1 ?? ""), executable: fixture.gpg, keyring: fixture.home)
                XCTAssertNil(decrypted.2); XCTAssertNil(decrypted.3)
                XCTAssertEqual(decrypted.1, sign ? fixture.own : nil)
                XCTAssertTrue(try XCTUnwrap(decrypted.0).suffix(expected.count).elementsEqual(expected))
                if body.contains("sample.bin") {
                    XCTAssertTrue(String(decoding: try XCTUnwrap(decrypted.0), as: UTF8.self).contains(attachment))
                    XCTAssertEqual(Data(base64Encoded: attachment), binary)
                }
            }
        }
    }

    func testIdentityBackupReviewAndRestore() throws {
        let backup = fixture.folder.appendingPathComponent("identity-backup")
        try FileManager.default.createDirectory(at: backup, withIntermediateDirectories: false)
        let secret = try KeyringCatalog.command(fixture.gpg, ["--no-options", "--homedir", fixture.home.path, "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--armor", "--export-secret-keys", fixture.own])
        let publicKey = try KeyringCatalog.command(fixture.gpg, ["--no-options", "--homedir", fixture.home.path, "--batch", "--armor", "--export", fixture.own])
        let certificate = try Data(contentsOf: fixture.home.appendingPathComponent("openpgp-revocs.d/" + fixture.own + ".rev"))
        let files = ["personal-secret-key.asc": Data(secret.output.utf8), "personal-public-key.asc": Data(publicKey.output.utf8), "revocation-certificate.rev": certificate]
        var hashes: [String: String] = [:]
        for (name, data) in files {
            try data.write(to: backup.appendingPathComponent(name))
            hashes[name] = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        }
        let manifest: [String: Any] = ["fingerprint": fixture.own, "sha256": hashes]
        try JSONSerialization.data(withJSONObject: manifest).write(to: backup.appendingPathComponent("backup-manifest.json"))
        let review = try IdentityImport.review(backup, executable: fixture.gpg)
        XCTAssertEqual(review.key.fingerprint, fixture.own)
        XCTAssertThrowsError(try IdentityImport.review(backup.appendingPathComponent("personal-public-key.asc"), executable: fixture.gpg))
        let direct = try IdentityImport.review(backup.appendingPathComponent("personal-secret-key.asc"), executable: fixture.gpg)
        XCTAssertEqual(direct.key.fingerprint, fixture.own)
        let restoredHome = fixture.folder.appendingPathComponent("restore-keys")
        _ = try IdentityImport.restore(review, executable: fixture.gpg, keyring: restoredHome, configureDialog: false)
        let keys = try KeyringCatalog.list(secret: true, executable: fixture.gpg, keyring: restoredHome)
        XCTAssertEqual(keys.count, 1); XCTAssertEqual(keys.first?.fingerprint, fixture.own)
        XCTAssertEqual(keys.first?.usable, true) // recovery certificate must not be imported as a revocation
        XCTAssertEqual(try Data(contentsOf: restoredHome.appendingPathComponent("openpgp-revocs.d/" + fixture.own + ".rev")), certificate)
        let signed = PersonalMessageSigner.sign(fixture.message, executable: fixture.gpg, keyring: restoredHome, fingerprint: fixture.own)
        let checked = IncomingSignatureVerifier.verify(try XCTUnwrap(signed.0, signed.1 ?? ""), executable: fixture.gpg, keyring: restoredHome)
        XCTAssertEqual(checked.1, fixture.own); XCTAssertNil(checked.2)
        _ = try IdentityImport.restore(review, executable: fixture.gpg, keyring: restoredHome, configureDialog: false)
        XCTAssertEqual(try KeyringCatalog.list(secret: true, executable: fixture.gpg, keyring: restoredHome).count, 1)
        try Data("damaged backup".utf8).write(to: backup.appendingPathComponent("personal-secret-key.asc"))
        XCTAssertThrowsError(try IdentityImport.review(backup, executable: fixture.gpg))
    }

    func testRecipientImportReviewRejectsSecretKeys() throws {
        let exported = try KeyringCatalog.command(fixture.gpg, ["--no-options", "--homedir", fixture.home.path, "--batch", "--armor", "--export", fixture.bob])
        let preview = try KeyringCatalog.preview(Data(exported.output.utf8), executable: fixture.gpg)
        XCTAssertEqual(preview.fingerprint, fixture.bob)
        XCTAssertEqual(preview.emails, ["bob@example.invalid"])
        let secret = try KeyringCatalog.command(fixture.gpg, ["--no-options", "--homedir", fixture.home.path, "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--armor", "--export-secret-keys", fixture.bob])
        XCTAssertThrowsError(try KeyringCatalog.preview(Data(secret.output.utf8), executable: fixture.gpg)) { error in
            XCTAssertTrue(error.localizedDescription.contains("private-key file"), error.localizedDescription)
        }
    }

    func testPublicKeyImportAndApprovalUseExactReviewedFingerprint() throws {
        let recipientHome = fixture.folder.appendingPathComponent("import-keyring")
        try FileManager.default.createDirectory(at: recipientHome, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let policy = fixture.folder.appendingPathComponent("import-recipients.json")
        let publicKey = try KeyringCatalog.command(fixture.gpg, ["--no-options", "--homedir", fixture.home.path, "--batch", "--armor", "--export", fixture.bob])
        let data = Data(publicKey.output.utf8)
        XCTAssertThrowsError(try KeyringCatalog.importRecipient(data, email: "someone@example.invalid", fingerprint: fixture.bob, executable: fixture.gpg, keyring: recipientHome, policy: policy))
        try KeyringCatalog.importRecipient(data, email: "bob@example.invalid", fingerprint: fixture.bob, executable: fixture.gpg, keyring: recipientHome, policy: policy)
        XCTAssertEqual(try KeyringCatalog.approvals(at: policy).first?.fingerprint, fixture.bob)
        XCTAssertEqual(try KeyringCatalog.list(executable: fixture.gpg, keyring: recipientHome).first?.fingerprint, fixture.bob)
    }

    func testMissingKeyAndDamagedCiphertextReturnNoPlaintext() throws {
        let result = PersonalMessageEncryptor.encode(fixture.message, executable: fixture.gpg, keyring: fixture.home, fingerprint: fixture.own, sign: false)
        let raw = try XCTUnwrap(result.0)
        let noKey = fixture.folder.appendingPathComponent("empty")
        try FileManager.default.createDirectory(at: noKey, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let unavailable = IncomingMessageDecryptor.decrypt(raw, executable: fixture.gpg, keyring: noKey)
        XCTAssertNil(unavailable.0); XCTAssertNotNil(unavailable.3)
        var lines = String(decoding: raw, as: UTF8.self).components(separatedBy: "\r\n")
        let start = try XCTUnwrap(lines.firstIndex(of: "-----BEGIN PGP MESSAGE-----"))
        let lineIndex = try XCTUnwrap(((start + 1)..<lines.count).first { lines[$0].count > 50 && !lines[$0].contains(":") })
        let index = lines[lineIndex].index(lines[lineIndex].startIndex, offsetBy: 24)
        lines[lineIndex].replaceSubrange(index...index, with: lines[lineIndex][index] == "A" ? "B" : "A")
        let bad = IncomingMessageDecryptor.decrypt(Data(lines.joined(separator: "\r\n").utf8), executable: fixture.gpg, keyring: fixture.home)
        XCTAssertNil(bad.0); XCTAssertNotNil(bad.3)
    }
}

private final class Fixture {
    static let email = "sender@example.invalid"
    static let identity = "Test Sender <sender@example.invalid>"
    let folder: URL
    let home: URL
    let gpg: String
    var own = ""
    var bob = ""
    let message = Data("From: Test Sender <sender@example.invalid>\r\nTo: bob@example.invalid\r\nSubject: GPGP fixture\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nSample café 🔐  \r\nSecond line.\r\n".utf8)

    init() throws {
        gpg = try XCTUnwrap(ProcessInfo.processInfo.environment["GPGP_TEST_GPG"] ?? KeyringCatalog.executable)
        folder = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("gpgp-suite-" + UUID().uuidString)
        home = folder.appendingPathComponent("keys")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        for identity in [Fixture.identity, "Bob <bob@example.invalid>"] {
            let result = try KeyringCatalog.command(gpg, ["--no-options", "--homedir", home.path, "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase", "", "--status-fd", "1", "--quick-generate-key", identity, "default", "default", "1d"], timeout: 30)
            guard result.status == 0 else { throw KeyringCatalog.failure("Fixture generation failed: " + result.error) }
        }
        let keys = try KeyringCatalog.list(executable: gpg, keyring: home)
        own = try XCTUnwrap(keys.first { $0.emails.contains(Fixture.email) }?.fingerprint)
        bob = try XCTUnwrap(keys.first { $0.emails.contains("bob@example.invalid") }?.fingerprint)
    }
    func close() {
        let gpgconf = URL(fileURLWithPath: gpg).deletingLastPathComponent().appendingPathComponent("gpgconf").path
        for location in [home, folder.appendingPathComponent("empty"), folder.appendingPathComponent("import-keyring"), folder.appendingPathComponent("restore-keys")] {
            _ = try? KeyringCatalog.command(gpgconf, ["--homedir", location.path, "--kill", "gpg-agent"])
        }
        try? FileManager.default.removeItem(at: folder)
    }
}
