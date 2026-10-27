import Foundation

enum PersonalMessageSigner {
    static func sign(_ raw: Data, sender: String) -> (Data?, String?) {
        let identity = PersonalSigningIdentity.lookup(sender: sender)
        guard let fingerprint = identity.0 else { return (nil, identity.1 ?? "Personal signing key unavailable.") }
        let paths = GnuPGRuntime.candidatePaths
        guard let executable = paths.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            return (nil, "GnuPG executable not found.")
        }
        return sign(raw, executable: executable,
                    keyring: FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".gnupg"), fingerprint: fingerprint)
    }

    static func sign(_ raw: Data, executable: String, keyring: URL, fingerprint: String) -> (Data?, String?) {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("gpgp-message-" + UUID().uuidString)
        do {
            let prepared = try OutgoingSignedMail.prepare(raw)
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            // Real draft content is temporary and is not retained as diagnostic output.
            defer { try? FileManager.default.removeItem(at: folder) }
            let content = folder.appendingPathComponent("content.mime")
            let signature = folder.appendingPathComponent("signature.asc")
            try prepared.content.write(to: content)
            let common = ["--no-options", "--homedir", keyring.path, "--batch", "--no-tty",
                          "--no-auto-check-trustdb", "--no-auto-key-retrieve", "--status-fd", "1"]
            let signed = try GnuPGSigningProbe.command(executable, common + ["--pinentry-mode", "ask",
                "--local-user", fingerprint + "!", "--armor", "--digest-algo", "SHA256",
                "--output", signature.path, "--detach-sign", content.path], in: folder, timeout: 180)
            guard signed.0 == 0 else {
                return (nil, "GnuPG signing failed or was cancelled. The message was not signed.\n\(signed.1.suffix(400))")
            }
            let verified = try GnuPGSigningProbe.command(executable, common + ["--verify", signature.path, content.path], in: folder)
            let valid = verified.1.split(separator: "\n").contains {
                let fields = $0.split(separator: " ")
                return fields.count > 2 && fields[0] == "[GNUPG:]" && fields[1] == "VALIDSIG" && fields[2] == Substring(fingerprint)
            }
            guard verified.0 == 0, valid else { return (nil, "The generated signature failed verification. No signed message was returned.") }
            let armor = try String(contentsOf: signature, encoding: .utf8)
            let packaged = OutgoingSignedMail.assemble(prepared, signature: armor)
            // Fail before sending if MIME encoding pushes the result beyond
            // this version’s receive limit or creates an unsupported package.
            _ = try IncomingSignedMail.parse(packaged)
            return (packaged, nil)
        } catch { return (nil, error.localizedDescription) }
    }
}
