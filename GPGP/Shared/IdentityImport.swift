import Foundation
import CryptoKit

nonisolated enum IdentityImport {
    struct Review: Sendable {
        let key: GPGPKey
        fileprivate let secret: Data
        fileprivate let revocation: Data?
    }
    private static func read(_ url: URL) throws -> Data {
        let handle = try FileHandle(forReadingFrom: url); defer { try? handle.close() }
        let data = try handle.read(upToCount: 5 * 1024 * 1024 + 1) ?? Data()
        guard !data.isEmpty, data.count <= 5 * 1024 * 1024 else { throw KeyringCatalog.failure("Choose a key file smaller than 5 MB.") }
        return data
    }
    static func review(_ url: URL, executable: String) throws -> Review {
        let directory = try url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory == true
        let secret = try read(directory ? url.appendingPathComponent("personal-secret-key.asc") : url)
        var revocation: Data?
        var expected: String?
        if directory {
            struct Manifest: Decodable { let fingerprint: String; let sha256: [String: String] }
            let manifest = try JSONDecoder().decode(Manifest.self, from: read(url.appendingPathComponent("backup-manifest.json")))
            guard KeyringCatalog.validFingerprint(manifest.fingerprint) else { throw KeyringCatalog.failure("Invalid backup fingerprint.") }
            expected = manifest.fingerprint
            for name in ["personal-secret-key.asc", "personal-public-key.asc", "revocation-certificate.rev"] {
                let data = name == "personal-secret-key.asc" ? secret : try read(url.appendingPathComponent(name))
                let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
                guard manifest.sha256[name] == hash else { throw KeyringCatalog.failure("Backup verification failed for \(name). Nothing was imported.") }
                if name == "revocation-certificate.rev" { revocation = data }
            }
        }
        let key = try inspect(secret, executable: executable)
        guard expected == nil || expected == key.fingerprint else { throw KeyringCatalog.failure("The private key does not match the backup fingerprint.") }
        return Review(key: key, secret: secret, revocation: revocation)
    }
    private static func inspect(_ data: Data, executable: String) throws -> GPGPKey {
        let folder = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("gpgp-import-review-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let input = folder.appendingPathComponent("identity.asc")
        try data.write(to: input)
        let result = try KeyringCatalog.command(executable, ["--no-options", "--homedir", folder.path, "--batch", "--no-tty", "--no-autostart",
            "--with-colons", "--import-options", "show-only", "--dry-run", "--import", input.path])
        let keys = KeyringCatalog.parse(result.output)
        guard result.status == 0, keys.count == 1, let key = keys.first, key.secret, !key.emails.isEmpty else {
            throw KeyringCatalog.failure("Choose one private identity key or its GPGP backup folder. A public key alone cannot restore your identity.")
        }
        return key
    }
    static func restore(_ review: Review, executable: String, keyring: URL = KeyringCatalog.home, configureDialog: Bool = true) throws -> String {
        let checked = try inspect(review.secret, executable: executable)
        guard checked.fingerprint == review.key.fingerprint else { throw KeyringCatalog.failure("The reviewed identity no longer matches.") }
        try FileManager.default.createDirectory(at: keyring, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        if configureDialog && !GnuPGRuntime.isBundled(executable) {
            let config = keyring.appendingPathComponent("gpg-agent.conf")
            if !FileManager.default.fileExists(atPath: config.path),
               let pinentry = ["/opt/homebrew/bin/pinentry-mac", "/usr/local/bin/pinentry-mac"].first(where: { FileManager.default.isExecutableFile(atPath: $0) }) {
                try Data(("pinentry-program " + pinentry + "\n").utf8).write(to: config, options: .withoutOverwriting)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: config.path)
                let gpgconf = URL(fileURLWithPath: executable).deletingLastPathComponent().appendingPathComponent("gpgconf").path
                _ = try KeyringCatalog.command(gpgconf, ["--homedir", keyring.path, "--reload", "gpg-agent"])
            }
        }
        let folder = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("gpgp-identity-import-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let input = folder.appendingPathComponent("identity.asc"); try review.secret.write(to: input)
        let imported = try KeyringCatalog.command(executable, ["--no-options", "--homedir", keyring.path, "--batch", "--no-tty", "--pinentry-mode", "ask", "--import", input.path], timeout: 180)
        guard imported.status == 0 else { throw KeyringCatalog.failure("Identity import did not finish or was cancelled. Any keys already imported were retained; your selected sender was not changed.") }
        let keys = try KeyringCatalog.list(secret: true, executable: executable, keyring: keyring)
        guard keys.contains(where: { $0.fingerprint == checked.fingerprint && $0.secret }) else { throw KeyringCatalog.failure("The private key was not found after import. Review your keyring before retrying.") }
        if let revocation = review.revocation {
            // Store the certificate as a recovery file. NEVER feed it to --import:
            // doing so would revoke the identity the user is trying to restore.
            let directory = keyring.appendingPathComponent("openpgp-revocs.d")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let target = directory.appendingPathComponent(checked.fingerprint + ".rev")
            if !FileManager.default.fileExists(atPath: target.path) {
                try revocation.write(to: target, options: .withoutOverwriting)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
            }
        }
        return "Identity imported: \(checked.title)\nFingerprint: \(checked.fingerprint)\nChoose its key and email above, then click Use This Identity. Your previous sender selection was kept."
    }
}
