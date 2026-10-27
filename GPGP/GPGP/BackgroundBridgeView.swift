import SwiftUI
import ServiceManagement

// The Objective-C name and method must match the helper's protocol.

struct BackgroundBridgeView: View {
    private let serviceName = "com.JimKelley.GPGP.bridge"
    private var service: SMAppService {
        .agent(plistName: "com.JimKelley.GPGP.bridge.plist")
    }
    @State private var status = ""
    @State private var result: String?
    @State private var connection: NSXPCConnection?
    @State private var request: UUID?
    @State private var updating = false

    var body: some View {
        GroupBox("Background helper") {
            VStack(alignment: .leading, spacing: 10) {
                Text("The helper lets the sandboxed Mail extension use your local GnuPG installation. Only this signed app and its extension can connect.")
                    .foregroundStyle(.secondary)
                Text(status)
                HStack {
                    Button("Enable Helper") {
                        do {
                            try service.register()
                            result = "Registration requested. Refresh status before testing."
                        } catch { result = "Registration failed: \(error.localizedDescription)" }
                        refresh()
                    }
                    Button("Disable Helper") {
                        updating = true
                        Task {
                            do { try await service.unregister(); result = "Helper unregistered." }
                            catch { result = "Unregister failed: \(error.localizedDescription)" }
                            updating = false
                            refresh()
                        }
                    }
                    Button("Restart Helper") {
                        updating = true
                        Task {
                            do {
                                try await service.unregister()
                                try service.register()
                                result = "Helper restarted. You can test the connection below."
                            } catch { result = "Restart failed: \(error.localizedDescription)" }
                            updating = false
                            refresh()
                        }
                    }
                    Button("Refresh Status", action: refresh)
                }
                .disabled(request != nil || updating)
                Button("Open Background Settings") { SMAppService.openSystemSettingsLoginItems() }
                Button("Test Background Connection", action: test)
                    .disabled(request != nil || updating)
                if let result { Text(result).textSelection(.enabled) }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(8)
        }
        .onAppear(perform: refresh)
        .onDisappear {
            request = nil
            connection?.invalidate()
            connection = nil
        }
    }

    private func refresh() {
        switch service.status {
        case .enabled: status = "Helper enabled."
        case .notRegistered: status = "Helper not registered."
        case .requiresApproval: status = "Allow GPGP in System Settings → General → Login Items & Extensions, then refresh."
        case .notFound: status = "Helper configuration not found in this app."
        @unknown default: status = "Unknown helper status."
        }
    }

    private func finish(_ id: UUID, _ message: String) {
        guard request == id else { return }
        request = nil
        result = message
        connection?.invalidate()
        connection = nil
    }

    private func test() {
        guard request == nil else { return }
        guard service.status == .enabled else {
            refresh()
            result = "Enable the helper and approve it if macOS requests approval."
            return
        }
        let id = UUID()
        request = id
        result = "Connecting…"
        let connection = NSXPCConnection(machServiceName: serviceName)
        self.connection = connection
        connection.setCodeSigningRequirement("anchor apple generic and certificate leaf[subject.OU] = \"MV65BFBFT7\" and identifier \"GPGPBridge\"")
        connection.remoteObjectInterface = NSXPCInterface(with: GPGPBridgeProtocol.self)
        connection.invalidationHandler = {
            Task { @MainActor in finish(id, "Connection invalidated. Check helper registration and approval.") }
        }
        connection.interruptionHandler = {
            Task { @MainActor in finish(id, "Helper connection interrupted.") }
        }
        connection.resume()
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
            let message = error.localizedDescription
            Task { @MainActor in finish(id, "Connection failed: \(message)") }
        }) as? GPGPBridgeProtocol else {
            finish(id, "Unable to create helper interface.")
            return
        }
        proxy.ping(id.uuidString) { reply in
            Task { @MainActor in
                finish(id, reply == id.uuidString ? "PASS: Background helper returned the matching XPC reply." : "FAIL: Unexpected helper reply.")
            }
        }
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(5))
            finish(id, "Background connection timed out.")
        }
    }
}
