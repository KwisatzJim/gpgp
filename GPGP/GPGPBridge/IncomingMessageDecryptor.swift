import Foundation

enum IncomingMessageDecryptor {
    // Decoded MIME, signing fingerprint, signing error, decryption error.
    static func decrypt(_ raw: Data) -> (Data?, String?, String?, String?) {
        let paths = GnuPGRuntime.candidatePaths
        guard let executable = paths.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            return (nil, nil, nil, "GnuPG not found. Message could not be decrypted.")
        }
        return decrypt(raw, executable: executable, keyring: FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".gnupg"))
    }

    static func decrypt(_ raw: Data, executable: String, keyring: URL) -> (Data?, String?, String?, String?) {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("gpgp-decrypt-" + UUID().uuidString)
        do {
            let parts = try IncomingEncryptedMail.parse(raw)
            guard FileManager.default.fileExists(atPath: keyring.path) else { return (nil, nil, nil, "Personal keyring not found.") }
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            defer { try? FileManager.default.removeItem(at: folder) }
            let encrypted = folder.appendingPathComponent("encrypted.asc")
            let plaintext = folder.appendingPathComponent("content.mime")
            try parts.encrypted.write(to: encrypted)
            let checked = try GnuPGSigningProbe.command(executable, ["--no-options", "--homedir", keyring.path,
                "--batch", "--no-tty", "--no-auto-check-trustdb", "--no-auto-key-retrieve", "--no-auto-key-import",
                "--pinentry-mode", "ask", "--max-output", "3145728", "--status-fd", "1",
                "--output", plaintext.path, "--decrypt", encrypted.path], in: folder, timeout: 165)
            let statuses = checked.1.split(separator: "\n").filter { $0.hasPrefix("[GNUPG:] ") }
            let good = statuses.contains("[GNUPG:] DECRYPTION_OKAY")
            let authenticated = statuses.contains { line in
                let fields = line.split(separator: " ")
                guard fields.count >= 4, fields[1] == "DECRYPTION_INFO" else { return false }
                return fields[2] != "0" || (fields.count > 4 && (Int(fields[4]) ?? 0) > 0)
            }
            let failed = statuses.contains { line in
                ["BADMDC", "DECRYPTION_FAILED", "ERROR", "FAILURE"].contains {
                    line == "[GNUPG:] " + $0 || line.hasPrefix("[GNUPG:] " + $0 + " ")
                }
            }
            guard checked.0 == 0, good, authenticated, !failed else {
                let missing = statuses.contains { $0.hasPrefix("[GNUPG:] NO_SECKEY ") }
                return (nil, nil, nil, missing ? "No matching private key is available to decrypt this message."
                        : "Decryption failed, was cancelled, or did not pass its integrity check. No decrypted content was returned.")
            }
            let entity = try Data(contentsOf: plaintext)
            guard entity.count <= 3145728 else { return (nil, nil, nil, "Decrypted message exceeds the supported size.") }
            switch IncomingEncryptedMail.entityType(entity) {
            case "text/plain", "text/html", "multipart/mixed", "multipart/alternative", "multipart/related": return (parts.restore(entity), nil, nil, nil)
            case "multipart/signed":
                let verified = IncomingSignatureVerifier.verify(entity, executable: executable, keyring: keyring)
                guard let decoded = verified.0 else {
                    return (nil, nil, verified.2, "Message decrypted, but the inner signed-email format is unsupported.")
                }
                let version = Data("MIME-Version: 1.0\r\n".utf8)
                guard decoded.starts(with: version) else {
                    return (nil, nil, verified.2, "Unsupported decoded inner MIME headers.")
                }
                return (parts.restore(Data(decoded.dropFirst(version.count))), verified.1, verified.2, nil)
            default: return (nil, nil, nil, "Message decrypted, but its MIME content type is not supported by this version.")
            }
        } catch { return (nil, nil, nil, "Message could not be decrypted: \(error.localizedDescription)") }
    }
}
