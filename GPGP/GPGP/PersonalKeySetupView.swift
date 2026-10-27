import SwiftUI
import AppKit

struct PersonalKeySetupView: View {
    let executable: String?
    @State private var creating = false
    @State private var confirmCreation = false
    @State private var showingCreation = false
    @State private var showingImport = false
    @State private var keyListRevision = 0
    @State private var result: String?
    @State private var backingUp = false
    @State private var backupResult: String?
    @State private var existing: [GPGPKey] = []
    @State private var checking = false
    @State private var selected: SenderIdentity?
    @State private var newName = ""
    @State private var newEmail = ""
    private var newIdentity: String { "\(newName.trimmingCharacters(in: .whitespaces)) <\(newEmail.trimmingCharacters(in: .whitespaces))>" }

    private var canCreate: Bool {
        let name = newName.trimmingCharacters(in: .whitespaces)
        return executable != nil && !creating && !backingUp && !name.isEmpty
            && !name.contains("<") && !name.contains(">")
            && !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
            && KeyringCatalog.normalizedEmail(newEmail) != nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
        HStack {
            Text("Manage your OpenPGP identities").font(.headline)
            Spacer()
            Button("Import Identity…") { showingImport = true }
                .disabled(executable == nil || creating || backingUp)
            Button("Create New Identity…") {
                result = nil
                showingCreation = true
            }
            .disabled(executable == nil || creating || backingUp)
        }
        SenderSelectionView(didSave: refresh).id(keyListRevision)
        GroupBox("Your personal email key") {
            VStack(alignment: .leading, spacing: 10) {
                Text(selected?.email ?? "No sender selected").font(.headline)
                ForEach(existing) { key in
                    VStack(alignment: .leading, spacing: 6) {
                        Label(key.usable ? "Personal key available" : "Key needs attention", systemImage: key.usable ? "checkmark.seal.fill" : "exclamationmark.triangle")
                            .foregroundStyle(key.usable ? Color.teal : Color.orange)
                        Text(key.fingerprint).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                        if let expires = key.expires { Text("Expires \(expires.formatted(date: .abbreviated, time: .omitted))").foregroundStyle(.secondary) }
                    }
                    .padding(.vertical, 6)
                }
                if existing.isEmpty {
                    Text("Select an existing identity above, or create a new one. Creating a key does not change the sender currently selected for Mail.")
                        .foregroundStyle(.secondary)
                }
                HStack {
                    Button("Refresh Key", action: refresh).disabled(creating || backingUp || checking)
                    Button("Export Public Key…", action: exportPublic).disabled(existing.count != 1 || creating || backingUp || checking)
                }
                Button(backingUp ? "Exporting backup—check for a passphrase dialog…" : "Back Up Personal Key") {
                    backUp()
                }
                .disabled(executable == nil || existing.count != 1 || selected == nil || creating || backingUp)
                Text("Backup includes your private key. Choose a secure destination; each backup gets a new folder.")
                    .font(.callout).foregroundStyle(.secondary)
                if let backupResult {
                    Text(backupResult).textSelection(.enabled)
                }
                if let result {
                    Text(result)
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(8)
        }
        }
        .onAppear(perform: refresh)
        .sheet(isPresented: $showingCreation) { creationSheet }
        .sheet(isPresented: $showingImport) {
            if let executable {
                IdentityImportView(executable: executable) { keyListRevision += 1; refresh() }
            }
        }
    }

    private var creationSheet: some View {
        VStack(alignment: .leading, spacing: 18) {
            Label("Create an OpenPGP identity", systemImage: "key.fill").font(.title2.bold())
            Text("A new identity gets its own signing key and encryption subkey, valid for one year. Your existing keys and selected sender are kept.")
                .foregroundStyle(.secondary)
            TextField("Name", text: $newName).textFieldStyle(.roundedBorder)
                .disabled(creating)
            TextField("Email address", text: $newEmail).textFieldStyle(.roundedBorder)
                .disabled(creating)
            Text("GnuPG’s macOS dialog will ask for a passphrase. Use a nonempty passphrase and keep it safe; GPGP never receives it.")
                .font(.callout).foregroundStyle(.secondary)
            if creating { ProgressView("Creating keys—check the GnuPG passphrase dialog…") }
            if let result {
                ScrollView { Text(result).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                    .frame(maxHeight: 160)
            }
            HStack {
                Button("Close") { showingCreation = false }.disabled(creating)
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Create Identity") { confirmCreation = true }
                    .buttonStyle(.borderedProminent).disabled(!canCreate)
            }
        }
        .padding(26).frame(width: 520)
        .interactiveDismissDisabled(creating)
        .confirmationDialog("Create a personal key for \(newIdentity)?", isPresented: $confirmCreation, titleVisibility: .visible) {
            Button("Create Identity") { create() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This initializes your personal GnuPG folder if needed and configures the macOS passphrase dialog when no agent configuration exists. It will not publish your key or send email.")
        }
    }

    private func create() {
        guard let executable, canCreate else { return }
        creating = true
        let identity = newIdentity
        Task {
            result = await Task.detached(priority: .userInitiated) {
                PersonalKeySetup.create(executable: executable, identity: identity)
            }.value
            creating = false
            keyListRevision += 1
            refresh()
        }
    }

    private func backUp() {
        guard let executable, let selected, !creating, !backingUp else { return }
        let panel = NSOpenPanel()
        panel.title = "Choose a secure destination for your private-key backup"
        panel.message = "GPGP will create a new backup folder here. Existing files will not be replaced."
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Back Up Here"
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        backingUp = true
        backupResult = nil
        Task {
            backupResult = await Task.detached(priority: .userInitiated) {
                PersonalKeyBackup.create(executable: executable, destination: destination, identity: selected.email, selectedFingerprint: selected.fingerprint)
            }.value
            backingUp = false
        }
    }

    private func refresh() {
        guard !checking else { return }
        checking = true
        Task {
            let loaded = await Task.detached { () -> ([GPGPKey], SenderIdentity?, String?) in
                do {
                    let selected = try SenderIdentity.load()
                    return (try KeyringCatalog.list(secret: true).filter { $0.fingerprint == selected?.fingerprint }, selected, nil)
                } catch { return ([], nil, error.localizedDescription) }
            }.value
            existing = loaded.0
            selected = loaded.1
            if let error = loaded.2 { result = error }
            checking = false
        }
    }

    private func exportPublic() {
        guard let executable, existing.count == 1, let key = existing.first else { return }
        let panel = NSSavePanel(); panel.title = "Export your public key"; panel.nameFieldStringValue = "GPGP-public-key.asc"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        backingUp = true
        Task {
            let message = await Task.detached { () -> String in
                do {
                    let exported = try KeyringCatalog.command(executable, ["--no-options", "--homedir", KeyringCatalog.home.path,
                        "--batch", "--armor", "--export", key.fingerprint])
                    guard exported.status == 0, exported.output.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") else {
                        return "Public-key export failed."
                    }
                    try Data(exported.output.utf8).write(to: url, options: .atomic)
                    return "Public key exported to \(url.path). This file can be shared; it contains no private key."
                } catch { return error.localizedDescription }
            }.value
            backupResult = message; backingUp = false
        }
    }
}
