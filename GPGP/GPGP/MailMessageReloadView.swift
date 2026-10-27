import SwiftUI
import MailKit

struct MailMessageReloadView: View {
    @State private var refreshing = false
    @State private var result: String?

    var body: some View {
        GroupBox("Reload a message in Mail") {
            VStack(alignment: .leading, spacing: 10) {
                Text("Select the test message in Mail, then refresh it here to request decoding with the updated extension.")
                    .foregroundStyle(.secondary)
                Button(refreshing ? "Requesting refresh…" : "Refresh Mail Message") {
                    refreshing = true
                    result = nil
                    MEExtensionManager.reloadVisibleMessages { error in
                        let message = error.map { "Refresh failed: \($0.localizedDescription)" }
                            ?? "Mail accepted the refresh request. Return to Mail to check the message. Mail may limit repeated refresh requests."
                        Task { @MainActor in
                            result = message
                            refreshing = false
                        }
                    }
                }
                .disabled(refreshing)
                if let result { Text(result).textSelection(.enabled) }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(8)
        }
    }
}
