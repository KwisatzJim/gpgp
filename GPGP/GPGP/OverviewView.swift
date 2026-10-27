import SwiftUI
import ServiceManagement
import AppKit

struct OverviewView: View {
    let executable: String?
    @State private var selected: SenderIdentity?
    @State private var personal: GPGPKey?
    @State private var recipients = 0
    @State private var helperEnabled = false
    @State private var checking = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack {
                VStack(alignment: .leading, spacing: 5) {
                    Text("Your mail, secured by your keys.").font(.title2.bold())
                    Text("Sign messages, encrypt for approved recipients, and verify incoming mail.")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Refresh", action: refresh).disabled(checking)
            }
            HStack(spacing: 12) {
                statusCard("GnuPG", value: executable == nil ? "Not detected" : "Installed", icon: "terminal", ready: executable != nil)
                statusCard("Mail helper", value: helperEnabled ? "Enabled" : "Needs setup", icon: "link", ready: helperEnabled)
                statusCard("Personal key", value: personal?.usable == true ? "Available" : "Needs attention", icon: "key", ready: personal?.usable == true)
            }
            GroupBox {
                HStack(alignment: .top, spacing: 16) {
                    Image(systemName: "person.crop.circle.fill").font(.system(size: 36)).foregroundStyle(.teal)
                    VStack(alignment: .leading, spacing: 8) {
                        Text(personal?.title ?? "Choose your identity").font(.headline)
                        Text(selected?.email ?? "Open My Key to get started").foregroundStyle(.secondary)
                        if let personal {
                            Text(personal.fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        } else { Text("Manage your signing identity and recovery files in My Key.").font(.callout).foregroundStyle(.secondary) }
                    }
                    Spacer()
                    VStack(alignment: .trailing, spacing: 5) {
                        Text("\(recipients)").font(.system(size: 30, weight: .semibold, design: .rounded))
                        Text("approved recipients").font(.caption).foregroundStyle(.secondary)
                    }
                }
                .padding(14).frame(maxWidth: .infinity, alignment: .leading)
            }
            GroupBox("Using GPGP in Mail") {
                VStack(alignment: .leading, spacing: 13) {
                    instruction("1", "Use your From address", detail: selected.map { "Choose \($0.email) in Mail’s compose window." } ?? "Select your sender email and private key in My Key first.")
                    instruction("2", "Choose signing or encryption", detail: "Use Mail’s security controls. Every encryption recipient needs an approved, usable public key.")
                    instruction("3", "Check the received message", detail: "Decryption and signature verification have separate results. Signing does not authenticate outer From and Subject headers.")
                }
                .padding(12).frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack(alignment: .top, spacing: 9) {
                Image(systemName: "info.circle").foregroundStyle(.secondary)
                Text("Keep Undo Send off in Mail → Settings → Composing. This Mail version crashes on signed messages in that path. Drafts remain unencrypted. Messages support plain text, HTML, and standard MIME attachments up to 2 MB. Inline PGP and encrypted Bcc are not supported.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            if let error { Text(error).font(.callout).foregroundStyle(.orange).textSelection(.enabled) }
            HStack {
                Label("Keys and cryptography stay on this Mac", systemImage: "desktopcomputer")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Open Mail") {
                    NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: "/System/Applications/Mail.app"), configuration: .init())
                }
            }
        }
        .onAppear(perform: refresh)
    }

    private func statusCard(_ title: String, value: String, icon: String, ready: Bool) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                HStack { Image(systemName: icon).foregroundStyle(.secondary); Spacer(); Image(systemName: ready ? "checkmark.circle.fill" : "circle.dashed").foregroundStyle(ready ? Color.teal : Color.orange) }
                Text(title).font(.caption).foregroundStyle(.secondary)
                Text(value).font(.headline)
            }.padding(10).frame(maxWidth: .infinity, alignment: .leading)
        }
    }
    private func instruction(_ number: String, _ title: String, detail: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text(number).font(.caption.bold()).frame(width: 24, height: 24).background(.teal.opacity(0.12), in: Circle())
            VStack(alignment: .leading, spacing: 3) { Text(title).font(.callout.bold()); Text(detail).font(.callout).foregroundStyle(.secondary) }
        }
    }
    private func refresh() {
        guard !checking else { return }
        checking = true
        helperEnabled = SMAppService.agent(plistName: "com.JimKelley.GPGP.bridge.plist").status == .enabled
        Task {
            let result = await Task.detached { () -> (GPGPKey?, Int, SenderIdentity?, String?) in
                do {
                    let selected = try SenderIdentity.load()
                    let keys = try KeyringCatalog.list(secret: true).filter { $0.fingerprint == selected?.fingerprint && $0.emails.contains(selected?.email ?? "") }
                    return (keys.count == 1 ? keys[0] : nil, try KeyringCatalog.approvals().count, selected, nil)
                } catch { return (nil, 0, nil, error.localizedDescription) }
            }.value
            personal = result.0; recipients = result.1; selected = result.2; error = result.3; checking = false
        }
    }
}
