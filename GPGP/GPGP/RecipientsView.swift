import SwiftUI
import AppKit

struct RecipientsView: View {
    let executable: String?
    @State private var keys: [GPGPKey] = []
    @State private var approvals: [RecipientApproval] = []
    @State private var pendingData: Data?
    @State private var preview: GPGPKey?
    @State private var email = ""
    @State private var verifiedFingerprint = false
    @State private var busy = false
    @State private var message: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("People you can encrypt to").font(.title2.bold())
                    Text("Your own key is included automatically so you can read Sent messages.")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Refresh", action: refresh).disabled(busy)
                Button("Import Public Key…", action: chooseKey).disabled(busy || executable == nil)
                    .buttonStyle(.borderedProminent)
            }
            GroupBox {
                if approvals.isEmpty {
                    VStack(spacing: 10) {
                        Image(systemName: "person.crop.circle.badge.key.fill").font(.system(size: 32)).foregroundStyle(.secondary)
                        Text("No recipient keys approved yet").font(.headline)
                        Text("Import a public key, compare its fingerprint with the recipient, then approve it for their email address.")
                            .foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 480)
                    }
                    .frame(maxWidth: .infinity).padding(24)
                } else {
                    List(approvals) { approval in
                        HStack(alignment: .top) {
                            Image(systemName: keyUsable(approval) ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                                .foregroundStyle(keyUsable(approval) ? Color.teal : Color.orange)
                            VStack(alignment: .leading, spacing: 5) {
                                Text(approval.email).font(.headline)
                                Text(approval.fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                                if !keyUsable(approval) { Text("Key unavailable or expired; encryption is blocked.").foregroundStyle(.orange) }
                            }
                            Spacer()
                            Button("Stop Using") { revoke(approval) }.disabled(busy)
                                .help("Removes approval only. The public key stays in your keyring.")
                        }
                        .padding(.vertical, 6)
                    }
                    .frame(minHeight: 130, maxHeight: 230)
                }
            }
            if let preview {
                GroupBox("Review public key") {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(preview.title).font(.headline)
                        Text(preview.fingerprint).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                        Picker("Use for", selection: $email) {
                            ForEach(preview.emails, id: \.self) { Text($0).tag($0) }
                        }
                        Text("Compare the fingerprint with the recipient using a trusted channel. The email label alone does not prove who owns the key.")
                            .font(.callout).foregroundStyle(.secondary)
                        Toggle("I verified this fingerprint with the recipient", isOn: $verifiedFingerprint)
                        HStack {
                            Button("Cancel") { self.preview = nil; pendingData = nil; verifiedFingerprint = false }
                            Spacer()
                            Button("Import and Approve", action: importKey)
                                .buttonStyle(.borderedProminent).disabled(busy || !verifiedFingerprint || email.isEmpty)
                        }
                    }
                    .padding(10)
                }
            }
            if busy { ProgressView().controlSize(.small) }
            if let message { Text(message).font(.callout).textSelection(.enabled) }
            Text("No keyserver lookups or automatic key downloads. Encrypted Bcc delivery is not supported; send separate messages for hidden recipients.")
                .font(.caption).foregroundStyle(.secondary)
            Spacer(minLength: 0)
        }
        .onAppear(perform: refresh)
    }

    private func keyUsable(_ approval: RecipientApproval) -> Bool {
        keys.contains { $0.fingerprint == approval.fingerprint && $0.usable && $0.canEncrypt && $0.emails.contains(approval.email) }
    }
    private func refresh() {
        guard !busy else { return }
        busy = true
        Task {
            let result = await Task.detached { () -> ([GPGPKey], [RecipientApproval], String?) in
                do { return (try KeyringCatalog.list(), try KeyringCatalog.approvals(), nil) }
                catch { return ([], [], error.localizedDescription) }
            }.value
            keys = result.0; approvals = result.1; message = result.2; busy = false
        }
    }
    private func chooseKey() {
        guard let executable, !busy else { return }
        let panel = NSOpenPanel(); panel.title = "Choose a recipient’s public key"
        panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        busy = true; message = nil; verifiedFingerprint = false
        Task {
            let result = await Task.detached { () -> (Data?, GPGPKey?, String?) in
                do {
                    let handle = try FileHandle(forReadingFrom: url); defer { try? handle.close() }
                    let data = try handle.read(upToCount: 5 * 1024 * 1024 + 1) ?? Data()
                    let key = try KeyringCatalog.preview(data, executable: executable)
                    return (data, key, nil)
                } catch { return (nil, nil, error.localizedDescription) }
            }.value
            pendingData = result.0; preview = result.1; email = result.1?.emails.first ?? ""
            message = result.2; busy = false
        }
    }
    private func importKey() {
        guard let executable, let data = pendingData, let key = preview, verifiedFingerprint, !busy else { return }
        let selectedEmail = email
        busy = true
        Task {
            let error = await Task.detached { () -> String? in
                do {
                    try KeyringCatalog.importRecipient(data, email: selectedEmail, fingerprint: key.fingerprint, executable: executable)
                    return nil
                } catch { return error.localizedDescription }
            }.value
            busy = false
            if let error { message = error }
            else {
                preview = nil; pendingData = nil; verifiedFingerprint = false
                refresh()
            }
        }
    }
    private func revoke(_ approval: RecipientApproval) {
        do {
            try KeyringCatalog.revoke(email: approval.email)
            approvals.removeAll { $0.email == approval.email }
            message = "Approval removed for \(approval.email). Its public key was kept."
        } catch { message = error.localizedDescription }
    }
}
