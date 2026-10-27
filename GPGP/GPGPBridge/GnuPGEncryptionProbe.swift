import Foundation

enum GnuPGEncryptionProbe {
    static func run() -> String {
        let candidates = GnuPGRuntime.candidatePaths
        guard let executable = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            return "FAIL: Helper could not find GnuPG."
        }
        let folder = URL(fileURLWithPath: "/private/tmp")
            .appendingPathComponent("gpgp-bridge-encrypt-" + UUID().uuidString)
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false,
                                                     attributes: [.posixPermissions: 0o700])
            let original = Data("GPGP helper encryption test.\r\nUnicode: café 🔐\r\n".utf8)
            let message = folder.appendingPathComponent("sample.txt")
            let encrypted = folder.appendingPathComponent("sample.gpg")
            let recovered = folder.appendingPathComponent("recovered.txt")
            try original.write(to: message)
            let common = ["--no-options", "--homedir", folder.path, "--batch", "--no-tty",
                          "--no-auto-check-trustdb", "--no-auto-key-retrieve", "--status-fd", "1"]
            let generated = try GnuPGSigningProbe.command(executable, common + ["--pinentry-mode", "loopback", "--passphrase", "",
                "--quick-generate-key", "GPGP Bridge Test <gpgp-bridge-test@example.invalid>", "default", "default", "1d"], in: folder)
            guard generated.0 == 0,
                  let created = generated.1.split(separator: "\n").first(where: { $0.hasPrefix("[GNUPG:] KEY_CREATED ") }),
                  let fingerprint = created.split(separator: " ").last else {
                return "FAIL: Encryption test key creation failed.\n\(generated.1.suffix(500))\nFolder: \(folder.path)"
            }
            // The trust override applies only to this new disposable keyring and exact recipient.
            let sealed = try GnuPGSigningProbe.command(executable, common + ["--trust-model", "always", "--recipient", String(fingerprint),
                "--output", encrypted.path, "--encrypt", message.path], in: folder)
            guard sealed.0 == 0 else { return "FAIL: Encryption failed.\n\(sealed.1.suffix(500))" }
            let opened = try GnuPGSigningProbe.command(executable, common + ["--pinentry-mode", "loopback", "--passphrase", "",
                "--output", recovered.path, "--decrypt", encrypted.path], in: folder)
            guard opened.0 == 0,
                  opened.1.split(separator: "\n").contains("[GNUPG:] DECRYPTION_OKAY") else {
                return "FAIL: Decryption failed.\n\(opened.1.suffix(500))"
            }
            guard try Data(contentsOf: recovered) == original else {
                return "FAIL: Recovered bytes differ from the original sample."
            }
            return "PASS: Helper encrypted and decrypted the sample.\nPASS: Recovered bytes match exactly, including Unicode and line endings.\nDisposable keys expire in one day. Test folder:\n\(folder.path)"
        } catch {
            return "FAIL: Helper encryption test: \(error.localizedDescription)\nFolder: \(folder.path)"
        }
    }
}
