import Foundation

nonisolated struct SenderIdentity: Codable, Equatable, Sendable {
    let email: String
    let fingerprint: String
    static var file: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/GPGP/sender.json")
    }
    static func load(at url: URL = file) throws -> SenderIdentity? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        let identity = try JSONDecoder().decode(Self.self, from: Data(contentsOf: url))
        guard KeyringCatalog.normalizedEmail(identity.email) == identity.email,
              KeyringCatalog.validFingerprint(identity.fingerprint), identity.fingerprint == identity.fingerprint.uppercased() else {
            throw KeyringCatalog.failure("The saved sender selection is invalid. Select your identity again in My Key.")
        }
        return identity
    }
    func validated(in keys: [GPGPKey]) throws -> GPGPKey {
        let matches = keys.filter { $0.fingerprint == fingerprint }
        guard matches.count == 1, let key = matches.first, key.secret, key.usable, key.canSign,
              key.emails.contains(email) else {
            throw KeyringCatalog.failure("The selected private signing key is missing, expired, revoked, or no longer matches this address. Review My Key in GPGP.")
        }
        return key
    }
    func save(keys: [GPGPKey], at url: URL = file) throws {
        guard KeyringCatalog.normalizedEmail(email) == email, KeyringCatalog.validFingerprint(fingerprint),
              fingerprint == fingerprint.uppercased() else { throw KeyringCatalog.failure("Invalid sender selection.") }
        _ = try validated(in: keys)
        // Refuse to silently overwrite corrupt configuration.
        _ = try Self.load(at: url)
        let parent = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try JSONEncoder().encode(self).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
