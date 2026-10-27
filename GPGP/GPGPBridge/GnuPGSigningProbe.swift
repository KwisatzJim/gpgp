import Foundation

enum GnuPGSigningProbe {
    static func run() -> String {
        let candidates = GnuPGRuntime.candidatePaths
        guard let executable = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            return "FAIL: Helper could not find GnuPG."
        }
        let folder = URL(fileURLWithPath: "/private/tmp")
            .appendingPathComponent("gpgp-bridge-test-" + UUID().uuidString)
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false,
                                                     attributes: [.posixPermissions: 0o700])
            let message = folder.appendingPathComponent("sample.txt")
            let altered = folder.appendingPathComponent("altered.txt")
            let signature = folder.appendingPathComponent("sample.sig")
            try Data("GPGP helper signing test.\r\nUnicode: café 🔐\r\n".utf8).write(to: message)
            try Data("GPGP helper signing test.\r\nChanged content.\r\n".utf8).write(to: altered)
            let common = ["--no-options", "--homedir", folder.path, "--batch", "--no-tty",
                          "--no-auto-check-trustdb", "--no-auto-key-retrieve", "--status-fd", "1"]
            let generated = try command(executable, common + ["--pinentry-mode", "loopback", "--passphrase", "",
                "--quick-generate-key", "GPGP Bridge Test <gpgp-bridge-test@example.invalid>", "ed25519", "sign", "1d"], in: folder)
            guard generated.0 == 0,
                  let created = generated.1.split(separator: "\n").first(where: { $0.hasPrefix("[GNUPG:] KEY_CREATED ") }),
                  let fingerprint = created.split(separator: " ").last else {
                return "FAIL: Test key creation failed.\n\(generated.1.suffix(500))\nFolder: \(folder.path)"
            }
            let signed = try command(executable, common + ["--pinentry-mode", "loopback", "--passphrase", "",
                "--local-user", String(fingerprint), "--output", signature.path, "--detach-sign", message.path], in: folder)
            guard signed.0 == 0 else { return "FAIL: Signing failed.\n\(signed.1.suffix(500))" }
            let verified = try command(executable, common + ["--verify", signature.path, message.path], in: folder)
            let valid = verified.1.split(separator: "\n").contains {
                let fields = $0.split(separator: " ")
                return fields.count > 2 && fields[0] == "[GNUPG:]" && fields[1] == "VALIDSIG" && fields[2] == fingerprint
            }
            guard verified.0 == 0, valid else { return "FAIL: Verification failed.\n\(verified.1.suffix(500))" }
            let rejected = try command(executable, common + ["--verify", signature.path, altered.path], in: folder)
            guard rejected.0 != 0, rejected.1.contains("[GNUPG:] BADSIG ") else {
                return "FAIL: Changed sample was not rejected as expected.\n\(rejected.1.suffix(500))"
            }
            return "PASS: Helper signed the sample and verified its signature.\nPASS: Changed sample rejected.\nDisposable keys expire in one day. Test folder:\n\(folder.path)"
        } catch {
            return "FAIL: Helper signing test: \(error.localizedDescription)\nFolder: \(folder.path)"
        }
    }

    static func command(_ executable: String, _ arguments: [String], in folder: URL, timeout seconds: TimeInterval = 10) throws -> (Int32, String) {
        let outputURL = folder.appendingPathComponent("output-" + UUID().uuidString)
        guard FileManager.default.createFile(atPath: outputURL.path, contents: nil,
                                            attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        let output = try FileHandle(forWritingTo: outputURL)
        defer {
            try? output.close()
            try? FileManager.default.removeItem(at: outputURL)
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = output
        try process.run()
        let timeout = DispatchWorkItem { if process.isRunning { process.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + seconds, execute: timeout)
        defer { timeout.cancel() }
        process.waitUntilExit()
        try output.close()
        return (process.terminationStatus, String(decoding: try Data(contentsOf: outputURL), as: UTF8.self))
    }
}
