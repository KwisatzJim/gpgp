import Foundation

nonisolated enum PersonalKeySetup {
    static func create(executable: String, identity: String) -> String {
        guard !identity.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              let start = identity.firstIndex(of: "<"), identity.hasSuffix(">"),
              !identity[..<start].trimmingCharacters(in: .whitespaces).isEmpty,
              !identity[..<start].contains(">"),
              KeyringCatalog.normalizedEmail(String(identity[identity.index(after: start)..<identity.index(before: identity.endIndex)])) != nil else {
            return "Enter a name and a valid email address. Key creation was not started."
        }
        let home = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".gnupg")
        do {
            guard let pinentry = GnuPGRuntime.pinentry(for: executable) else {
                return "No macOS passphrase dialog found. Install pinentry-mac before creating a personal key."
            }
            // The app's explicit Create action authorizes initializing this personal keyring.
            if !FileManager.default.fileExists(atPath: home.path) {
                try FileManager.default.createDirectory(at: home, withIntermediateDirectories: false,
                                                         attributes: [.posixPermissions: 0o700])
            }
            if !GnuPGRuntime.isBundled(executable) {
            let config = home.appendingPathComponent("gpg-agent.conf")
            let setting = "pinentry-program \(pinentry)"
            if FileManager.default.fileExists(atPath: config.path) {
                let current = try String(contentsOf: config, encoding: .utf8)
                guard current.components(separatedBy: .newlines).contains(setting) else {
                    return "An existing gpg-agent.conf needs review before configuring the passphrase dialog. No configuration was overwritten and key creation was not started."
                }
            } else {
                try Data((setting + "\n").utf8).write(to: config, options: .withoutOverwriting)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: config.path)
            }
            }
            let gpgconf = URL(fileURLWithPath: executable).deletingLastPathComponent().appendingPathComponent("gpgconf").path
            guard FileManager.default.isExecutableFile(atPath: gpgconf) else {
                return "Could not find gpgconf alongside GnuPG. Key creation was not started."
            }
            let reloaded = try command(gpgconf, ["--homedir", home.path, "--reload", "gpg-agent"], timeout: 10)
            guard reloaded.0 == 0 else {
                return "Unable to reload the passphrase-dialog configuration.\n\(reloaded.1)"
            }
            let common = ["--no-options", "--homedir", home.path, "--batch", "--no-tty"]
            // No --yes: GnuPG refuses to generate another key with the same user ID.
            // Passphrases are handled by the agent's native pinentry, never this app.
            let generated = try command(executable, common + ["--pinentry-mode", "ask", "--status-fd", "1",
                "--quick-generate-key", identity, "default", "default", "1y"], timeout: 180)
            guard generated.0 == 0,
                  let record = generated.1.split(separator: "\n").first(where: { $0.hasPrefix("[GNUPG:] KEY_CREATED B ") }),
                  let fingerprint = record.split(separator: " ").last,
                  fingerprint.count == 40, fingerprint.allSatisfy({ $0.isHexDigit }) else {
                return "Key creation did not complete successfully. It may have been cancelled, or this identity may already have a key. Existing files were retained.\n\(generated.1.suffix(1400))"
            }
            let checked = try command(executable, common + ["--with-colons", "--fingerprint", "--list-secret-keys", String(fingerprint)], timeout: 15)
            let rows = checked.1.split(separator: "\n").map { $0.split(separator: ":", omittingEmptySubsequences: false) }
            let signing = rows.contains { $0.count > 11 && $0[0] == "sec" && $0[11].contains("s") }
            let encryption = rows.contains { $0.count > 11 && $0[0] == "ssb" && $0[11].contains("e") }
            let matchesIdentity = KeyringCatalog.parse(checked.1).contains { $0.fingerprint == String(fingerprint) && $0.identities.contains(identity) }
            guard checked.0 == 0, signing, encryption, matchesIdentity else {
                return "A key was created, but the follow-up check needs review. Do not create another key.\nFingerprint: \(fingerprint)\n\(checked.1.suffix(1200))"
            }
            return "Personal key created and checked.\n\(identity)\nFingerprint: \(fingerprint)\nSigning key and encryption subkey available.\nExpiration: one year.\nNext: close this sheet, choose the new key and email in Sender identity, and click Use This Identity when ready. Back up the key before using it for important email."
        } catch {
            return "Personal-key setup stopped: \(error.localizedDescription)\nExisting files were retained."
        }
    }

    static func command(_ executable: String, _ arguments: [String], timeout: TimeInterval) throws -> (Int32, String) {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("gpgp-setup-" + UUID().uuidString)
        guard FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        let output = try FileHandle(forWritingTo: url)
        defer {
            try? output.close()
            try? FileManager.default.removeItem(at: url)
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = output
        try process.run()
        let deadline = DispatchWorkItem { if process.isRunning { process.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: deadline)
        defer { deadline.cancel() }
        process.waitUntilExit()
        try output.close()
        return (process.terminationStatus, String(decoding: try Data(contentsOf: url), as: UTF8.self))
    }
}
