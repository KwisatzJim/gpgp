import Foundation

enum IncomingSignatureVerifier {
    static func verify(_ raw: Data) -> (Data?, String?, String?) {
        let paths = GnuPGRuntime.candidatePaths
        guard let executable = paths.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            return (nil, nil, "GnuPG not found. Signature could not be checked.")
        }
        return verify(raw, executable: executable, keyring: FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".gnupg"))
    }

    static func verify(_ raw: Data, executable: String, keyring: URL) -> (Data?, String?, String?) {
        let parts: IncomingSignedMail.Parts
        do { parts = try IncomingSignedMail.parse(raw) }
        catch { return (nil, nil, error.localizedDescription) }
        guard FileManager.default.fileExists(atPath: keyring.path) else {
            return (parts.decoded, nil, "No local public keyring is available. Signature not verified.")
        }
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("gpgp-verify-" + UUID().uuidString)
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            defer { try? FileManager.default.removeItem(at: folder) }
            let content = folder.appendingPathComponent("content.mime")
            let signature = folder.appendingPathComponent("signature.asc")
            try parts.content.write(to: content)
            try parts.signature.write(to: signature)
            let checked = try GnuPGSigningProbe.command(executable,
                ["--no-options", "--homedir", keyring.path, "--batch", "--no-tty", "--no-autostart",
                 "--no-auto-check-trustdb", "--no-auto-key-retrieve", "--no-auto-key-import", "--status-fd", "1",
                 "--verify", signature.path, content.path], in: folder)
            let statuses = checked.1.split(separator: "\n").filter { $0.hasPrefix("[GNUPG:] ") }
            let valid = statuses.filter { $0.hasPrefix("[GNUPG:] VALIDSIG ") }
            let rejected = statuses.contains { line in
                ["BADSIG", "ERRSIG", "NO_PUBKEY", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "FAILURE"].contains {
                    line.hasPrefix("[GNUPG:] " + $0 + " ")
                }
            }
            guard checked.0 == 0, !rejected, valid.count == 1 else {
                let missing = statuses.contains { $0.hasPrefix("[GNUPG:] NO_PUBKEY ") }
                return (parts.decoded, nil, missing ? "Signer’s public key is not in your local keyring. Signature not verified."
                        : "Signature verification failed. The message may have changed, or the signing key may be expired or revoked.")
            }
            let fields = valid[0].split(separator: " ")
            guard fields.count > 9, fields[2].count == 40, fields[2].allSatisfy({ $0.isHexDigit }), fields[9] == Substring(parts.digest) else {
                return (parts.decoded, nil, "Unsupported signature fingerprint or digest algorithm.")
            }
            return (parts.decoded, String(fields[2]), nil)
        } catch { return (parts.decoded, nil, "Signature could not be checked: \(error.localizedDescription)") }
    }
}
