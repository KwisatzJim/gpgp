import Foundation

nonisolated enum PersonalSigningIdentity {
    static func lookup(sender: String) -> (String?, String?) {
        do {
            guard let selected = try SenderIdentity.load() else {
                return (nil, "Choose a sender email and private key in GPGP → My Key.")
            }
            return lookup(sender: sender, selected: selected)
        } catch { return (nil, error.localizedDescription) }
    }

    static func lookup(sender: String, selected: SenderIdentity, executable: String? = nil, keyring: URL? = nil) -> (String?, String?) {
        guard KeyringCatalog.normalizedEmail(sender) == selected.email else {
            return (nil, "Choose \(selected.email) as the From address in Mail, or change your selection in GPGP → My Key.")
        }
        guard let executable = executable ?? KeyringCatalog.executable else { return (nil, "The helper could not find GnuPG.") }
        let home = keyring ?? KeyringCatalog.home
        do {
            let result = try KeyringCatalog.command(executable, ["--no-options", "--homedir", home.path, "--batch", "--no-tty",
                "--no-auto-check-trustdb", "--with-colons", "--fingerprint", "--list-secret-keys", selected.fingerprint])
            guard result.status == 0 else { return (nil, "GnuPG could not read the selected private key.") }
            _ = try selected.validated(in: KeyringCatalog.parse(result.output))
            let primaries = result.output.split(separator: "\n").map { $0.split(separator: ":", omittingEmptySubsequences: false) }.filter { $0.first == "sec" }
            // The signer pins the primary key with !. Do not offer a key whose
            // primary signing secret is unavailable or only has a signing subkey.
            guard primaries.count == 1, let row = primaries.first, row.count > 14,
                  row[11].contains("s"), row[14] != "#" else {
                return (nil, "This version requires an available primary signing key. Signing-subkey-only identities are not supported yet.")
            }
            return (selected.fingerprint, nil)
        } catch { return (nil, error.localizedDescription) }
    }
}
