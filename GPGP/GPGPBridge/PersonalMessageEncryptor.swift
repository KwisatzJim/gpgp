import Foundation

enum PersonalMessageEncryptor {
    static func recipientKeys(_ recipients: [String]) -> ([String]?, String?) {
        guard !recipients.isEmpty, recipients.count <= 100 else { return (nil, "Add at least one recipient; this version supports up to 100.") }
        do {
            guard let selected = try SenderIdentity.load() else { return (nil, "Select your sender in GPGP → My Key.") }
            let own = PersonalSigningIdentity.lookup(sender: selected.email, selected: selected)
            guard let ownFingerprint = own.0 else { return (nil, own.1) }
            return (try resolve(recipients: recipients, ownFingerprint: ownFingerprint, ownEmail: selected.email,
                                keys: KeyringCatalog.list(), approvals: KeyringCatalog.approvals()), nil)
        } catch { return (nil, error.localizedDescription) }
    }

    static func resolve(recipients: [String], ownFingerprint: String, ownEmail: String, keys: [GPGPKey], approvals: [RecipientApproval]) throws -> [String] {
        guard !recipients.isEmpty, recipients.count <= 100 else { throw KeyringCatalog.failure("Add a recipient before encrypting.") }
        guard let own = keys.first(where: { $0.fingerprint == ownFingerprint }), own.usable, own.canEncrypt,
              own.emails.contains(ownEmail) else {
            throw KeyringCatalog.failure("Your personal key has no usable encryption subkey.")
        }
        var selected = Set([ownFingerprint]) // Keep Sent messages readable by the sender.
        for raw in recipients {
            guard let email = KeyringCatalog.normalizedEmail(raw) else { throw KeyringCatalog.failure("Invalid recipient email address.") }
            let fingerprint: String
            if email == ownEmail { fingerprint = ownFingerprint }
            else {
                let matches = approvals.filter { $0.email == email }
                guard matches.count == 1 else { throw KeyringCatalog.failure("Approve a public-key fingerprint for \(email) in GPGP → Recipients.") }
                fingerprint = matches[0].fingerprint
            }
            let matches = keys.filter { $0.fingerprint == fingerprint }
            guard matches.count == 1, let key = matches.first, key.usable, key.canEncrypt, key.emails.contains(email) else {
                throw KeyringCatalog.failure("The approved key for \(email) is unavailable, expired, revoked, or no longer matches that address.")
            }
            selected.insert(fingerprint)
        }
        return selected.sorted()
    }

    static func encode(_ raw: Data, sender: String, recipients: [String], sign: Bool) -> (Data?, String?) {
        let selected: SenderIdentity
        do {
            guard let identity = try SenderIdentity.load() else { return (nil, "Select your sender in GPGP → My Key.") }
            selected = identity
        } catch { return (nil, error.localizedDescription) }
        let own = PersonalSigningIdentity.lookup(sender: sender, selected: selected)
        guard let fingerprint = own.0, let executable = executablePath else { return (nil, own.1 ?? "Personal signing identity unavailable.") }
        let fingerprints: [String]
        do {
            fingerprints = try resolve(recipients: recipients, ownFingerprint: fingerprint, ownEmail: selected.email,
                                       keys: KeyringCatalog.list(), approvals: KeyringCatalog.approvals())
        } catch { return (nil, error.localizedDescription) }
        return encode(raw, executable: executable, keyring: personalHome, fingerprint: fingerprint, sign: sign, recipients: fingerprints)
    }

    static func encode(_ raw: Data, executable: String, keyring: URL, fingerprint: String, sign: Bool, recipients: [String]? = nil) -> (Data?, String?) {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("gpgp-encrypt-message-" + UUID().uuidString)
        do {
            let prepared = try OutgoingSignedMail.prepare(raw)
            let content: Data
            if sign {
                let signed = PersonalMessageSigner.sign(raw, executable: executable, keyring: keyring, fingerprint: fingerprint)
                guard let signedMail = signed.0 else { return (nil, signed.1 ?? "Signing failed; no encrypted substitute was returned.") }
                content = try signedEntity(signedMail)
            } else { content = prepared.content }
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            defer { try? FileManager.default.removeItem(at: folder) }
            let input = folder.appendingPathComponent("content.mime")
            let output = folder.appendingPathComponent("encrypted.asc")
            try content.write(to: input)
            // Every recipient is pinned to a fingerprint approved by the user.
            // Revalidate key identity, expiry and capabilities for each send.
            let recipientArguments = (recipients ?? [fingerprint]).flatMap { ["--recipient", $0] }
            let encrypted = try GnuPGSigningProbe.command(executable, ["--no-options", "--homedir", keyring.path,
                "--batch", "--no-tty", "--no-auto-check-trustdb", "--no-auto-key-retrieve",
                "--trust-model", "always", "--armor", "--status-fd", "1"] + recipientArguments + [
                "--output", output.path, "--encrypt", input.path], in: folder)
            guard encrypted.0 == 0, encrypted.1.split(separator: "\n").contains("[GNUPG:] END_ENCRYPTION") else {
                return (nil, "Encryption failed. No unencrypted substitute was returned.\n\(encrypted.1.suffix(400))")
            }
            let armor = try String(contentsOf: output, encoding: .utf8)
            let packaged = assemble(headers: prepared.headers, armor: armor)
            // Verify the actual package, not merely its multipart Content-Type.
            // Never return a header-only message as successful encryption.
            _ = try IncomingEncryptedMail.parse(packaged)
            return (packaged, nil)
        } catch { return (nil, error.localizedDescription) }
    }

    private static var personalHome: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".gnupg")
    }
    private static var executablePath: String? {
        GnuPGRuntime.candidatePaths.first {
            FileManager.default.isExecutableFile(atPath: $0)
        }
    }
    private static func signedEntity(_ raw: Data) throws -> Data {
        guard let text = String(data: raw, encoding: .utf8), let split = text.range(of: "\r\n\r\n") else {
            throw OutgoingSignedMail.failure("Signed MIME message was incomplete.")
        }
        var headers: [String] = []
        for line in text[..<split.lowerBound].components(separatedBy: "\r\n") {
            if line.hasPrefix(" ") || line.hasPrefix("\t"), !headers.isEmpty { headers[headers.count - 1] += "\r\n" + line }
            else { headers.append(line) }
        }
        let mimeHeaders = headers.filter { $0.lowercased().hasPrefix("content-") }
        guard mimeHeaders.contains(where: { $0.lowercased().hasPrefix("content-type: multipart/signed;") }) else {
            throw OutgoingSignedMail.failure("Signing did not produce a signed MIME entity.")
        }
        return Data((mimeHeaders.joined(separator: "\r\n") + "\r\n\r\n" + text[split.upperBound...]).utf8)
    }
    private static func assemble(headers: [String], armor: String) -> Data {
        let boundary = "gpgp_" + UUID().uuidString
        let normalized = armor.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\n", with: "\r\n")
        let lines = headers + ["MIME-Version: 1.0", "Content-Type: multipart/encrypted;",
            " protocol=\"application/pgp-encrypted\";", " boundary=\"\(boundary)\"", "", "--\(boundary)",
            "Content-Type: application/pgp-encrypted", "", "Version: 1", "", "--\(boundary)",
            "Content-Type: application/octet-stream; name=\"encrypted.asc\"", "Content-Transfer-Encoding: 7bit",
            "Content-Disposition: inline; filename=\"encrypted.asc\"", "", normalized, "--\(boundary)--", ""]
        return Data(lines.joined(separator: "\r\n").utf8)
    }
}
