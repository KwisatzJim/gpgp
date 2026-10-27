import SwiftUI
import AppKit

struct IdentityImportView: View {
    let executable: String
    let didImport: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var review: IdentityImport.Review?
    @State private var busy = false
    @State private var completed = false
    @State private var message: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Import an OpenPGP identity", systemImage: "square.and.arrow.down").font(.title2.bold())
            Text("Choose a GPGP backup folder or a private-key file. Public recipient keys belong in Recipients.").foregroundStyle(.secondary)
            Button("Choose Backup or Private Key…", action: choose).disabled(busy)
            if let review {
                GroupBox("Review identity") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(review.key.title).font(.headline)
                        Text(review.key.emails.joined(separator: ", "))
                        Text(review.key.fingerprint).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                        if !review.key.usable { Text("This key is expired, revoked, or disabled. Importing it will not make it usable for new mail.").foregroundStyle(.orange) }
                    }.padding(8).frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            Text("The private key is added to this Mac’s GnuPG keyring. GnuPG may ask for its existing passphrase. An existing agent configuration is kept; a new setup uses pinentry-mac when installed. Your selected sender will not change.")
                .font(.callout).foregroundStyle(.secondary)
            if busy { ProgressView("Working—check for a GnuPG passphrase dialog…") }
            if let message { Text(message).font(.callout).textSelection(.enabled) }
            HStack {
                Button("Close") { dismiss() }.disabled(busy).keyboardShortcut(.cancelAction)
                Spacer()
                Button("Import Identity", action: restore).buttonStyle(.borderedProminent)
                    .disabled(review == nil || busy || completed)
            }
        }.padding(26).frame(width: 550)
        .interactiveDismissDisabled(busy)
    }
    private func choose() {
        let panel = NSOpenPanel(); panel.title = "Choose a GPGP backup folder or private-key file"
        panel.canChooseDirectories = true; panel.canChooseFiles = true; panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        busy = true; review = nil; message = nil; completed = false
        Task {
            let loaded = await Task.detached { () -> (IdentityImport.Review?, String?) in
                do { return (try IdentityImport.review(url, executable: executable), nil) }
                catch { return (nil, error.localizedDescription) }
            }.value
            review = loaded.0; message = loaded.1; busy = false
        }
    }
    private func restore() {
        guard let review, !busy, !completed else { return }
        busy = true
        Task {
            let result = await Task.detached { () -> (Bool, String) in
                do { return (true, try IdentityImport.restore(review, executable: executable)) }
                catch { return (false, error.localizedDescription) }
            }.value
            busy = false; completed = result.0; message = result.1
            didImport()
        }
    }
}
