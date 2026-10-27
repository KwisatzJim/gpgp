import Foundation
import Darwin

nonisolated struct GPGPKey: Identifiable, Hashable, Sendable {
    let fingerprint: String
    let identities: [String]
    let emails: [String]
    let canSign: Bool
    let canEncrypt: Bool
    let usable: Bool
    let expires: Date?
    let secret: Bool
    var id: String { fingerprint }
    var title: String { identities.first ?? "OpenPGP key" }
}

nonisolated struct RecipientApproval: Codable, Identifiable, Hashable, Sendable {
    let email: String
    let fingerprint: String
    let approvedAt: Date
    var id: String { email }
}

nonisolated enum KeyringCatalog {
    static var home: URL { FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".gnupg") }
    static var executable: String? {
        GnuPGRuntime.candidatePaths.first {
            FileManager.default.isExecutableFile(atPath: $0)
        }
    }
    static var policyFile: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/GPGP/recipients.json")
    }
    static func failure(_ message: String) -> NSError {
        NSError(domain: "com.JimKelley.GPGP.Keyring", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
    static func validFingerprint(_ value: String) -> Bool {
        [40, 64].contains(value.count) && value.allSatisfy { $0.isHexDigit }
    }
    static func normalizedEmail(_ value: String) -> String? {
        let email = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard email.count <= 254, email.range(of: #"^[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+$"#, options: .regularExpression) != nil,
              !email.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return nil }
        return email
    }

    static func list(secret: Bool = false, executable: String? = nil, keyring: URL? = nil) throws -> [GPGPKey] {
        let keyring = keyring ?? home
        guard FileManager.default.fileExists(atPath: keyring.path) else { return [] }
        guard let executable = executable ?? Self.executable else { throw failure("GnuPG is not installed.") }
        let result = try command(executable, ["--no-options", "--homedir", keyring.path, "--batch", "--no-tty",
            "--no-auto-check-trustdb", "--with-colons", "--fingerprint", secret ? "--list-secret-keys" : "--list-keys"])
        guard result.status == 0 else { throw failure("Unable to read the keyring. " + result.error) }
        return parse(result.output)
    }

    static func parse(_ listing: String, now: Date = Date()) -> [GPGPKey] {
        struct Pending {
            var fingerprint = ""
            var identities: [String] = []
            var emails: [String] = []
            let capabilities: String
            let validity: String
            let expires: Date?
            let secret: Bool
        }
        var current: Pending?
        var keys: [GPGPKey] = []
        func finish() {
            guard let key = current, validFingerprint(key.fingerprint) else { return }
            let usable = !["r", "e", "d", "i"].contains(key.validity) && !key.capabilities.contains("D")
                && (key.expires == nil || key.expires! > now)
            keys.append(GPGPKey(fingerprint: key.fingerprint, identities: key.identities, emails: key.emails,
                canSign: key.capabilities.contains("S"), canEncrypt: key.capabilities.contains("E"),
                usable: usable, expires: key.expires, secret: key.secret))
        }
        for line in listing.split(separator: "\n") {
            let row = line.split(separator: ":", omittingEmptySubsequences: false)
            guard let type = row.first else { continue }
            if type == "pub" || type == "sec" {
                finish()
                guard row.count > 11 else { current = nil; continue }
                let seconds = TimeInterval(row[6]) ?? 0
                current = Pending(capabilities: String(row[11]), validity: String(row[1]),
                                  expires: seconds > 0 ? Date(timeIntervalSince1970: seconds) : nil, secret: type == "sec")
            } else if type == "fpr", row.count > 9, current?.fingerprint.isEmpty == true {
                current?.fingerprint = String(row[9]).uppercased()
            } else if type == "uid", row.count > 9, !["r", "e", "d", "i"].contains(String(row[1])) {
                let uid = decode(String(row[9]))
                current?.identities.append(uid)
                let email: String?
                if let start = uid.lastIndex(of: "<"), uid.hasSuffix(">") {
                    email = normalizedEmail(String(uid[uid.index(after: start)..<uid.index(before: uid.endIndex)]))
                } else { email = normalizedEmail(uid) }
                if let email, current?.emails.contains(email) == false { current?.emails.append(email) }
            }
        }
        finish()
        return keys
    }

    private static func decode(_ value: String) -> String {
        let bytes = Array(value.utf8)
        var result = Data(); var index = 0
        while index < bytes.count {
            if bytes[index] == 92, index + 3 < bytes.count, bytes[index + 1] == 120,
               let byte = UInt8(String(decoding: bytes[(index + 2)...(index + 3)], as: UTF8.self), radix: 16) {
                result.append(byte); index += 4
            } else { result.append(bytes[index]); index += 1 }
        }
        return String(decoding: result, as: UTF8.self)
    }

    static func approvals(at url: URL = policyFile) throws -> [RecipientApproval] {
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        let result = try JSONDecoder().decode([RecipientApproval].self, from: Data(contentsOf: url))
        guard Set(result.map(\.email)).count == result.count,
              result.allSatisfy({ normalizedEmail($0.email) == $0.email && validFingerprint($0.fingerprint) }) else {
            throw failure("The recipient approval file needs review. It has not been changed.")
        }
        return result.sorted { $0.email < $1.email }
    }
    static func approve(email: String, fingerprint: String, at url: URL = policyFile) throws {
        guard let email = normalizedEmail(email), validFingerprint(fingerprint) else { throw failure("Invalid recipient identity.") }
        var entries = try approvals(at: url)
        entries.removeAll { $0.email == email }
        entries.append(RecipientApproval(email: email, fingerprint: fingerprint.uppercased(), approvedAt: Date()))
        try save(entries, to: url)
    }
    static func revoke(email: String, at url: URL = policyFile) throws {
        try save(approvals(at: url).filter { $0.email != email }, to: url)
    }
    private static func save(_ entries: [RecipientApproval], to url: URL) throws {
        let directory = url.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        try JSONEncoder().encode(entries.sorted { $0.email < $1.email }).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    static func preview(_ data: Data, executable: String) throws -> GPGPKey {
        guard data.count <= 5 * 1024 * 1024 else { throw failure("Public-key files must be smaller than 5 MB.") }
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("gpgp-key-preview-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let file = folder.appendingPathComponent("key.pgp"); try data.write(to: file)
        let result = try command(executable, ["--no-options", "--homedir", folder.path, "--batch", "--no-tty", "--no-autostart",
            "--with-colons", "--import-options", "show-only", "--dry-run", "--import", file.path])
        let rows = result.output.split(separator: "\n")
        guard !rows.contains(where: { $0.hasPrefix("sec:") || $0.hasPrefix("ssb:") }) else {
            throw failure("This is a private-key file. The Recipients tab accepts public keys only.")
        }
        let keys = parse(result.output)
        guard result.status == 0, keys.count == 1, let key = keys.first, !key.emails.isEmpty else {
            throw failure("Choose a file containing exactly one public key with an email identity.")
        }
        // show-only output may not aggregate capabilities; a real keyring check
        // after import is authoritative for encryption availability.
        return key
    }

    static func importRecipient(_ data: Data, email: String, fingerprint: String, executable: String,
                                keyring: URL? = nil, policy: URL? = nil) throws {
        let home = keyring ?? Self.home
        let previewed = try preview(data, executable: executable)
        guard previewed.fingerprint == fingerprint, let email = normalizedEmail(email), previewed.emails.contains(email) else {
            throw failure("The selected public key no longer matches the reviewed identity.")
        }
        guard FileManager.default.fileExists(atPath: home.path) else { throw failure("Create your own key before importing recipient keys.") }
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("gpgp-key-import-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let file = folder.appendingPathComponent("public-key.pgp"); try data.write(to: file)
        let imported = try command(executable, ["--no-options", "--homedir", home.path, "--batch", "--no-tty",
            "--import-options", "import-minimal", "--import", file.path])
        guard imported.status == 0 else { throw failure("Public-key import failed. " + imported.error) }
        guard let key = try list(executable: executable, keyring: home).first(where: { $0.fingerprint == fingerprint }),
              key.usable, key.canEncrypt, key.emails.contains(email) else {
            throw failure("The key was imported for verification, but has no usable encryption key for this email. It was not approved for encryption.")
        }
        try approve(email: email, fingerprint: fingerprint, at: policy ?? policyFile)
    }

    struct CommandResult: Sendable { let status: Int32; let output: String; let error: String }
    static func command(_ executable: String, _ arguments: [String], timeout: TimeInterval = 15) throws -> CommandResult {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("gpgp-key-command-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let outURL = folder.appendingPathComponent("stdout"), errURL = folder.appendingPathComponent("stderr")
        for file in [outURL, errURL] {
            guard FileManager.default.createFile(atPath: file.path, contents: nil, attributes: [.posixPermissions: 0o600]) else { throw CocoaError(.fileWriteUnknown) }
        }
        let output = try FileHandle(forWritingTo: outURL), errors = try FileHandle(forWritingTo: errURL)
        defer { try? output.close(); try? errors.close() }
        let process = Process(); process.executableURL = URL(fileURLWithPath: executable); process.arguments = arguments
        process.standardInput = FileHandle.nullDevice; process.standardOutput = output; process.standardError = errors
        try process.run()
        let deadline = DispatchWorkItem { if process.isRunning { process.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: deadline)
        defer { deadline.cancel() }
        process.waitUntilExit(); try output.close(); try errors.close()
        let outData = try Data(contentsOf: outURL), errData = try Data(contentsOf: errURL)
        guard outData.count <= 5 * 1024 * 1024, errData.count <= 5 * 1024 * 1024 else { throw failure("GnuPG returned too much key metadata.") }
        return CommandResult(status: process.terminationStatus, output: String(decoding: outData, as: UTF8.self),
                             error: String(decoding: errData.prefix(2000), as: UTF8.self))
    }
}
