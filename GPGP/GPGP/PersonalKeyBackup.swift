import Foundation
import CryptoKit

nonisolated enum PersonalKeyBackup {
    static func create(executable: String, destination: URL, keyring: URL? = nil,
                       identity: String, selectedFingerprint: String) -> String {
        let home = keyring ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".gnupg")
        let folder = destination.appendingPathComponent("GPGP-Key-Backup-" + UUID().uuidString)
        do {
            guard FileManager.default.fileExists(atPath: home.path) else {
                return "No personal keyring found. Nothing was exported."
            }
            let common = ["--no-options", "--homedir", home.path, "--batch", "--no-tty", "--no-auto-check-trustdb"]
            let listed = try PersonalKeySetup.command(executable, common + ["--with-colons", "--fingerprint", "--list-secret-keys", selectedFingerprint], timeout: 15)
            let rows = listed.1.split(separator: "\n").map { $0.split(separator: ":", omittingEmptySubsequences: false) }
            guard listed.0 == 0, rows.filter({ $0.first == "sec" }).count == 1,
                  let fpr = rows.first(where: { $0.first == "fpr" }), fpr.count > 9,
                  fpr[9] == Substring(selectedFingerprint), KeyringCatalog.validFingerprint(selectedFingerprint) else {
                return "Could not identify exactly one personal secret key for \(identity). Nothing was exported."
            }
            let fingerprint = String(fpr[9])
            let revocation = home.appendingPathComponent("openpgp-revocs.d").appendingPathComponent(fingerprint + ".rev")
            guard FileManager.default.fileExists(atPath: revocation.path) else {
                return "The revocation certificate is missing. Backup stopped before exporting keys; existing keys are unchanged."
            }
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false,
                                                     attributes: [.posixPermissions: 0o700])
            let secret = folder.appendingPathComponent("personal-secret-key.asc")
            let publicKey = folder.appendingPathComponent("personal-public-key.asc")
            let exportedSecret = try PersonalKeySetup.command(executable, common + ["--pinentry-mode", "ask", "--armor", "--output", secret.path,
                "--export-secret-keys", fingerprint], timeout: 180)
            guard exportedSecret.0 == 0 else {
                return "Secret-key export did not complete. Partial backup retained at:\n\(folder.path)\n\(exportedSecret.1.suffix(500))"
            }
            let exportedPublic = try PersonalKeySetup.command(executable, common + ["--armor", "--output", publicKey.path, "--export", fingerprint], timeout: 15)
            guard exportedPublic.0 == 0 else {
                return "Public-key export failed. Partial backup retained at:\n\(folder.path)"
            }
            for (file, recordType) in [(secret, "sec"), (publicKey, "pub")] {
                let checked = try PersonalKeySetup.command(executable, common + ["--with-colons", "--import-options", "show-only", "--dry-run", "--import", file.path], timeout: 15)
                let records = checked.1.split(separator: "\n").map { $0.split(separator: ":", omittingEmptySubsequences: false) }
                let fingerprints = records.filter { $0.first == "fpr" && $0.count > 9 }
                guard checked.0 == 0, records.filter({ $0.first == Substring(recordType) }).count == 1,
                      fingerprints.first?[9] == Substring(fingerprint) else {
                    return "Export verification needs review. Partial backup retained at:\n\(folder.path)"
                }
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
            }
            let savedRevocation = folder.appendingPathComponent("revocation-certificate.rev")
            try FileManager.default.copyItem(at: revocation, to: savedRevocation)
            guard try Data(contentsOf: savedRevocation) == Data(contentsOf: revocation) else {
                throw CocoaError(.fileReadCorruptFile)
            }
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: savedRevocation.path)
            var hashes: [String: String] = [:]
            for file in [secret, publicKey, savedRevocation] {
                hashes[file.lastPathComponent] = SHA256.hash(data: try Data(contentsOf: file)).map { String(format: "%02x", $0) }.joined()
            }
            let manifest: [String: Any] = ["identity": identity, "fingerprint": fingerprint,
                "created": ISO8601DateFormatter().string(from: Date()), "sha256": hashes,
                "verification": "Export fingerprints checked; revocation certificate compared byte for byte. Restore not yet tested."]
            try JSONSerialization.data(withJSONObject: manifest, options: [.prettyPrinted, .sortedKeys])
                .write(to: folder.appendingPathComponent("backup-manifest.json"), options: .withoutOverwriting)
            let instructions = """
            GPGP personal-key backup
            Identity: \(identity)
            Fingerprint: \(fingerprint)

            personal-secret-key.asc is PRIVATE. Keep this backup in a secure location.
            The secret-key export retains the key's passphrase protection, if assigned.
            personal-public-key.asc can be shared with correspondents.
            revocation-certificate.rev can invalidate your key; keep it private.
            GnuPG prefixes the revocation armor with a colon to prevent accidental import.

            Fingerprints and file hashes were checked. A restore has not yet been tested.
            Your original keyring was not modified by this export.
            """
            try Data(instructions.utf8).write(to: folder.appendingPathComponent("README.txt"), options: .withoutOverwriting)
            return "Backup exported and fingerprints checked.\nRevocation certificate copied and checked.\n\(folder.path)\nKeep this folder in a secure backup location. A restore test is still needed."
        } catch {
            return "Backup stopped: \(error.localizedDescription)\nAny partial backup remains at:\n\(folder.path)\nOriginal keys were retained."
        }
    }
}
