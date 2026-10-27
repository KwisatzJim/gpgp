import MailKit
import AppKit


final class ComposeSessionHandler: NSObject, MEComposeSessionHandler {
    func mailComposeSessionDidBegin(_ session: MEComposeSession) {}
    func mailComposeSessionDidEnd(_ session: MEComposeSession) {}
    func viewController(for session: MEComposeSession) -> MEExtensionViewController {
        let controller = MailBridgeProbeController()
        controller.composeSession = session
        return controller
    }
}

@MainActor final class MailBridgeProbeController: MEExtensionViewController {
    var composeSession: MEComposeSession?
    private let status = NSTextField(wrappingLabelWithString: "Choose a check when you need connection details.")
    private lazy var button = NSButton(title: "Test Helper Connection", target: self, action: #selector(test))
    private lazy var versionButton = NSButton(title: "Test GnuPG Through Helper", target: self, action: #selector(testVersion))
    private lazy var signingButton = NSButton(title: "Test Signing Through Helper", target: self, action: #selector(testSigning))
    private lazy var encryptionButton = NSButton(title: "Test Encryption Through Helper", target: self, action: #selector(testEncryption))
    private lazy var identityButton = NSButton(title: "Check Personal Signing Key", target: self, action: #selector(checkIdentity))
    private var connection: NSXPCConnection?
    private var request: UUID?

    override func loadView() {
        let title = NSTextField(labelWithString: "GPGP")
        title.font = .boldSystemFont(ofSize: 18)
        let description = NSTextField(wrappingLabelWithString: "Use Mail’s security controls to sign or encrypt on send. Manage approved recipients in the GPGP app. Plain text, HTML, and standard MIME attachments up to 2 MB are supported.")
        let notice = NSTextField(wrappingLabelWithString: "Drafts remain unencrypted. Keep Undo Send off in Mail’s Composing settings.")
        notice.textColor = .secondaryLabelColor
        let tabs = NSTabView()
        func addTab(_ label: String, views: [NSView]) {
            let item = NSTabViewItem(identifier: label)
            item.label = label
            let content = NSStackView(views: views)
            content.orientation = .vertical
            content.alignment = .leading
            content.spacing = 12
            content.edgeInsets = NSEdgeInsets(top: 16, left: 16, bottom: 16, right: 16)
            item.view = content
            tabs.addTabViewItem(item)
        }
        addTab("Message", views: [description, identityButton, notice])
        addTab("Diagnostics", views: [NSTextField(wrappingLabelWithString: "These checks use disposable keys and never send mail."), button, versionButton, signingButton, encryptionButton])
        tabs.heightAnchor.constraint(equalToConstant: 220).isActive = true
        status.isSelectable = true
        status.font = .systemFont(ofSize: 12)
        let stack = NSStackView(views: [title, tabs, status])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        view = NSView(frame: NSRect(x: 0, y: 0, width: 480, height: 440))
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            stack.topAnchor.constraint(equalTo: view.topAnchor, constant: 20),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: view.bottomAnchor, constant: -20),
            tabs.widthAnchor.constraint(equalTo: stack.widthAnchor)
        ])
        preferredContentSize = NSSize(width: 480, height: 440)
    }

    override func viewDidDisappear() {
        super.viewDidDisappear()
        request = nil
        connection?.invalidate()
        connection = nil
        button.isEnabled = true
        versionButton.isEnabled = true
        signingButton.isEnabled = true
        encryptionButton.isEnabled = true
        identityButton.isEnabled = true
    }

    private func finish(_ id: UUID, _ message: String) {
        guard request == id else { return }
        request = nil
        status.stringValue = message
        button.isEnabled = true
        versionButton.isEnabled = true
        signingButton.isEnabled = true
        encryptionButton.isEnabled = true
        identityButton.isEnabled = true
        connection?.invalidate()
        connection = nil
    }

    @objc private func test() {
        connect(checkVersion: false)
    }

    @objc private func testVersion() {
        connect(checkVersion: true)
    }

    @objc private func testSigning() {
        connect(checkVersion: false, checkSigning: true)
    }

    @objc private func testEncryption() {
        connect(checkVersion: false, checkEncryption: true)
    }

    @objc private func checkIdentity() {
        connect(checkVersion: false, checkIdentity: true)
    }

    private func connect(checkVersion: Bool, checkSigning: Bool = false, checkEncryption: Bool = false, checkIdentity: Bool = false) {
        guard request == nil else { return }
        let id = UUID()
        request = id
        button.isEnabled = false
        versionButton.isEnabled = false
        signingButton.isEnabled = false
        encryptionButton.isEnabled = false
        identityButton.isEnabled = false
        status.stringValue = "Connecting…"
        let connection = NSXPCConnection(machServiceName: "com.JimKelley.GPGP.bridge")
        self.connection = connection
        connection.setCodeSigningRequirement("anchor apple generic and certificate leaf[subject.OU] = \"MV65BFBFT7\" and identifier \"GPGPBridge\"")
        connection.remoteObjectInterface = NSXPCInterface(with: GPGPBridgeProtocol.self)
        connection.invalidationHandler = { [weak self] in
            Task { @MainActor in self?.finish(id, "Connection invalidated. Check that the helper is enabled in GPGP.") }
        }
        connection.interruptionHandler = { [weak self] in
            Task { @MainActor in self?.finish(id, "Helper connection interrupted.") }
        }
        connection.resume()
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ [weak self] error in
            let message = error.localizedDescription
            Task { @MainActor in self?.finish(id, "Connection failed: \(message)") }
        }) as? GPGPBridgeProtocol else {
            finish(id, "Unable to create helper interface.")
            return
        }
        if checkIdentity {
            guard let sender = composeSession?.mailMessage.fromAddress.addressString else {
                finish(id, "Mail did not provide a valid From address for this draft.")
                return
            }
            status.stringValue = "Checking personal signing key for \(sender)…"
            proxy.signingKey(for: sender) { [weak self] fingerprint, error in
                Task { @MainActor in
                    self?.finish(id, fingerprint.map { "READY: Personal signing key matches \(sender).\nFingerprint: \($0)\nThis check did not sign or send the draft." }
                        ?? error ?? "No signing key was returned.")
                }
            }
        } else if checkEncryption {
            status.stringValue = "Creating disposable keys and testing encryption…"
            proxy.testEncryption { [weak self] reply in
                Task { @MainActor in self?.finish(id, String(reply.prefix(1000))) }
            }
        } else if checkSigning {
            status.stringValue = "Creating disposable keys and testing signing…"
            proxy.testSigning { [weak self] reply in
                Task { @MainActor in self?.finish(id, String(reply.prefix(1000))) }
            }
        } else if checkVersion {
            proxy.gnuPGVersion { [weak self] reply in
                Task { @MainActor in self?.finish(id, String(reply.prefix(600))) }
            }
        } else {
        proxy.ping(id.uuidString) { [weak self] reply in
            Task { @MainActor in
                self?.finish(id, reply == id.uuidString
                             ? "PASS: Sandboxed Mail extension received the matching helper reply."
                             : "FAIL: Unexpected helper reply.")
            }
        }
        }
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(checkSigning || checkEncryption ? 50 : 10))
            self?.finish(id, "Connection timed out. Check helper status in GPGP.")
        }
    }
}
