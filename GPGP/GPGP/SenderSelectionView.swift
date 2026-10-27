import SwiftUI

struct SenderSelectionView: View {
    let didSave: () -> Void
    @State private var keys: [GPGPKey] = []
    @State private var fingerprint = ""
    @State private var email = ""
    @State private var current: SenderIdentity?
    @State private var busy = false
    @State private var message: String?
    private var selectedKey: GPGPKey? { keys.first { $0.fingerprint == fingerprint } }

    var body: some View {
        GroupBox("Sender identity") {
            VStack(alignment: .leading, spacing: 12) {
                Text("Choose the private key and email address GPGP will use. This must match the From address in Mail.")
                    .foregroundStyle(.secondary)
                if keys.isEmpty {
                    Text("No usable private signing keys found. Create a key below or import an existing private key with GnuPG, then refresh.")
                } else {
                    Picker("Private key", selection: $fingerprint) {
                        Text("Choose a key").tag("")
                        ForEach(keys) { key in
                            Text(key.title + " · " + key.fingerprint.suffix(16)).tag(key.fingerprint)
                        }
                    }
                    if let key = selectedKey {
                        Text(key.fingerprint).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                        Picker("Sender email", selection: $email) {
                            ForEach(key.emails, id: \.self) { Text($0).tag($0) }
                        }
                    }
                }
                HStack {
                    Button("Refresh Keys", action: refresh).disabled(busy)
                    Spacer()
                    Button("Use This Identity", action: save)
                        .buttonStyle(.borderedProminent)
                        .disabled(busy || selectedKey == nil || email.isEmpty || current == SenderIdentity(email: email, fingerprint: fingerprint))
                }
                if let current {
                    Text("Mail uses \(current.email) · \(current.fingerprint.suffix(16))")
                        .font(.callout).foregroundStyle(.secondary)
                }
                if let message { Text(message).font(.callout).textSelection(.enabled) }
            }.padding(8).frame(maxWidth: .infinity, alignment: .leading)
        }
        .onAppear(perform: refresh)
        .onChange(of: fingerprint) { _, _ in
            if let key = selectedKey, !key.emails.contains(email) { email = key.emails.first ?? "" }
        }
    }
    private func refresh() {
        guard !busy else { return }
        busy = true
        Task {
            let loaded = await Task.detached { () -> ([GPGPKey], SenderIdentity?, String?) in
                do { return (try KeyringCatalog.list(secret: true).filter { $0.usable && $0.canSign && !$0.emails.isEmpty }, try SenderIdentity.load(), nil) }
                catch { return ([], nil, error.localizedDescription) }
            }.value
            keys = loaded.0; current = loaded.1; message = loaded.2
            fingerprint = current?.fingerprint ?? (keys.count == 1 ? keys[0].fingerprint : "")
            email = current?.email ?? selectedKey?.emails.first ?? ""
            busy = false
        }
    }
    private func save() {
        let candidate = SenderIdentity(email: email, fingerprint: fingerprint)
        busy = true
        Task {
            let error = await Task.detached { () -> String? in
                do {
                    let keys = try KeyringCatalog.list(secret: true)
                    let check = PersonalSigningIdentity.lookup(sender: candidate.email, selected: candidate)
                    guard check.0 == candidate.fingerprint else { return check.1 ?? "Signing key unavailable." }
                    try candidate.save(keys: keys)
                    return nil
                } catch { return error.localizedDescription }
            }.value
            busy = false
            if let error { message = error }
            else { current = candidate; message = "Identity saved. Choose this From address in Mail. Existing keys and recipient approvals were kept."; didSave() }
        }
    }
}
