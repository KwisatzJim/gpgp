//
//  ContentView.swift
//  GPGP
//
//  Created by Jim Kelley on 10/25/26.
//

import SwiftUI
import AppKit

struct ContentView: View {
    @State private var detectedPath: String?
    @State private var hasChecked = false
    @State private var selectedURL: URL?
    @State private var selectionError: String?
    @State private var versionResult: String?
    @State private var keyResult: String?
    @State private var testKeyHome: String?
    @State private var testKeyResult: String?
    @State private var isTesting = false
    @State private var bridgeResult: String?

    private var candidatePaths: [String] { GnuPGRuntime.candidatePaths }

    @AppStorage("selectedTab") private var selectedTab = "overview"
    @State private var diagnosticSection = "tests"

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 14) {
                Image("BrandIcon").resizable().frame(width: 64, height: 64)
                VStack(alignment: .leading, spacing: 3) {
                    Text("GPGP").font(.system(size: 27, weight: .semibold, design: .rounded))
                    Text("OpenPGP for Apple Mail").foregroundStyle(.secondary)
                }
                Spacer()
                Text("LOCAL · PRIVATE").font(.system(.caption2, design: .rounded).weight(.semibold))
                    .tracking(1.4).foregroundStyle(.secondary)
            }
            .padding(.horizontal, 25).padding(.vertical, 18)
            Divider()
            TabView(selection: $selectedTab) {
                page { OverviewView(executable: detectedPath) }
                    .tabItem { Label("Overview", systemImage: "square.grid.2x2") }.tag("overview")
                page {
                    Text("Your identity and recovery").font(.title2.bold())
                    PersonalKeySetupView(executable: detectedPath)
                }
                .tabItem { Label("My Key", systemImage: "key") }.tag("key")
                page { RecipientsView(executable: detectedPath) }
                    .tabItem { Label("Recipients", systemImage: "person.2") }.tag("recipients")
                page {
                    Text("Mail and GnuPG").font(.title2.bold())
                    BackgroundBridgeView()
                    installationCard
                }
                .tabItem { Label("Connection", systemImage: "link") }.tag("connection")
                page {
                    HStack {
                        Text("Diagnostics").font(.title2.bold())
                        Spacer()
                        Picker("Section", selection: $diagnosticSection) {
                            Text("Local tests").tag("tests")
                            Text("Troubleshooting").tag("help")
                        }.pickerStyle(.segmented).frame(width: 310)
                    }
                    if diagnosticSection == "tests" { testCard }
                    else {
                        MailMessageReloadView()
                        helperProbeCard
                        GroupBox("Current compatibility") {
                            Text("Plain text, HTML, and standard MIME attachments up to 2 MB are supported. Leave Undo Send off. Drafts remain unencrypted. Encrypted Bcc delivery and inline PGP are not available. Message security details distinguish decryption from verified signatures.")
                                .frame(maxWidth: .infinity, alignment: .leading).padding(10)
                        }
                    }
                }
                .tabItem { Label("Diagnostics", systemImage: "stethoscope") }.tag("diagnostics")
            }
            .padding(16)
        }
        .frame(minWidth: 800, idealWidth: 860, minHeight: 680, idealHeight: 740)
        .onAppear(perform: checkInstallation)
    }

    private func page<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18, content: content)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(22)
        }
    }

    private var installationCard: some View {
        GroupBox("GnuPG installation") {
                VStack(alignment: .leading, spacing: 10) {
                    if let detectedPath {
                        Label("GnuPG executable found", systemImage: "checkmark.circle")
                            .foregroundStyle(.green)
                        Text(detectedPath)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                        Text("GPGP uses its included GnuPG engine when packaged. Development builds can use Homebrew or GPG Suite.")
                            .foregroundStyle(.secondary)
                    } else {
                        Label(hasChecked ? "GnuPG not detected" : "Ready to check", systemImage: "magnifyingglass")
                        Text("Install GnuPG and pinentry-mac, then check again. Your keyring stays on this Mac.")
                            .foregroundStyle(.secondary)
                    }

                    HStack {
                        Button("Check Again", action: checkInstallation)

                    }
                    .disabled(isTesting)
                    Button(isTesting ? "Testing…" : "Test GnuPG", action: testGnuPG)
                        .disabled(detectedPath == nil || isTesting)
                    if let versionResult {
                        ScrollView {
                            Text(versionResult)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .frame(height: 160)
                    }
                    if let selectionError {
                        Text(selectionError)
                            .foregroundStyle(.red)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
            }
    }

    private var testCard: some View {
        GroupBox("Disposable test keys") {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Creates an unprotected test identity for gpgp-test@example.invalid, expiring in one day. Use it only for testing. The keys live in a separate temporary folder and may be removed by macOS.")
                        .foregroundStyle(.secondary)
                    HStack {
                        Button("Create Test Keys", action: createTestKeys)
                            .disabled(detectedPath == nil || isTesting || testKeyHome != nil)
                        Button("Check Test Keys") {
                            guard let testKeyHome else { return }
                            runDiagnostic(arguments: ["--no-options", "--homedir", testKeyHome,
                                                      "--batch", "--no-tty", "--no-auto-check-trustdb",
                                                      "--fingerprint", "--list-keys"],
                                          checkingKeys: false, testKeyOperation: true)
                        }
                        .disabled(testKeyHome == nil || isTesting)
                    }
                    Button("Sign and Verify Test", action: signAndVerifyTest)
                        .disabled(testKeyHome == nil || detectedPath == nil || isTesting)
                    Button("Encrypt and Decrypt Test", action: encryptAndDecryptTest)
                        .disabled(testKeyHome == nil || detectedPath == nil || isTesting)
                    Button("PGP/MIME Signing Test", action: signedMailTest)
                        .disabled(testKeyHome == nil || detectedPath == nil || isTesting)
                    Button("PGP/MIME Encryption Test", action: encryptedMailTest)
                        .disabled(testKeyHome == nil || detectedPath == nil || isTesting)
                    if let testKeyHome {
                        Text(testKeyHome)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    if let testKeyResult {
                        ScrollView([.horizontal, .vertical]) {
                            Text(testKeyResult)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                        }
                        .frame(height: 150)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
            }
    }

    private var helperProbeCard: some View {
        GroupBox("GnuPG helper") {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Checks the helper executable bundled inside this copy of GPGP. For the running service, use Connection → Test Background Connection.")
                        .foregroundStyle(.secondary)
                    Button("Test Helper Connection", action: testHelper)
                        .disabled(isTesting)
                    if let bridgeResult {
                        Text(bridgeResult).textSelection(.enabled)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
            }
    }

    private func testHelper() {
        guard !isTesting else { return }
        guard let executable = Bundle.main.url(forAuxiliaryExecutable: "GPGPBridge") else {
            bridgeResult = "Bundled helper not found. Rebuild the GPGP app."
            return
        }
        isTesting = true
        bridgeResult = "Testing…"
        Task {
            let result = await Task.detached {
                BridgeProbe.run(executable: executable)
            }.value
            bridgeResult = result
            isTesting = false
        }
    }

    private func checkInstallation() {
        versionResult = nil
        selectionError = nil
        if let selectedURL {
            validateSelection(selectedURL)
            return
        }
        detectedPath = candidatePaths.first {
            FileManager.default.isExecutableFile(atPath: $0)
        }
        hasChecked = true
    }

    private func chooseExecutable() {
        let panel = NSOpenPanel()
        panel.title = "Choose the GnuPG executable"
        panel.message = "Press ⌘⇧G, enter /opt/homebrew/bin, then select gpg."
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.resolvesAliases = true
        panel.prompt = "Choose"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        versionResult = nil
        selectedURL = url
        validateSelection(url)
    }

    private func validateSelection(_ url: URL) {
        let hasAccess = url.startAccessingSecurityScopedResource()
        defer {
            if hasAccess { url.stopAccessingSecurityScopedResource() }
        }
        hasChecked = true
        detectedPath = nil
        selectionError = nil
        do {
            // Homebrew's bin/gpg is a symbolic link to its versioned installation.
            let resolvedURL = url.resolvingSymlinksInPath()
            guard resolvedURL.lastPathComponent == "gpg" else {
                selectionError = "Choose the file named gpg. Selected: \(url.lastPathComponent)"
                return
            }
            // Verify read access granted by the picker without launching the program.
            let handle = try FileHandle(forReadingFrom: resolvedURL)
            defer { try? handle.close() }
            _ = try handle.read(upToCount: 4)
            detectedPath = resolvedURL.path
        } catch {
            selectionError = "Unable to read this file: \(error.localizedDescription)"
        }
    }

    private func testGnuPG() {
        runDiagnostic(arguments: ["--version"], checkingKeys: false)
    }

    private func checkKeys() {
        let home = ProcessInfo.processInfo.environment["GNUPGHOME"]
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".gnupg").path
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: home, isDirectory: &isDirectory), isDirectory.boolValue else {
            keyResult = "No GnuPG keyring folder found at \(home). Nothing was created."
            return
        }
        let keyrings = ["pubring.kbx", "pubring.gpg"].map {
            URL(fileURLWithPath: home).appendingPathComponent($0).path
        }.filter { FileManager.default.fileExists(atPath: $0) }
        guard !keyrings.isEmpty else {
            keyResult = "No pubring.kbx or pubring.gpg found in \(home). Nothing was created.\nIf you use the newer keyboxd storage, this initial check does not inspect it."
            return
        }
        let keyringArguments = keyrings.flatMap { ["--keyring", $0] }
        runDiagnostic(arguments: ["--no-options", "--homedir", home, "--batch", "--no-tty",
                                  "--no-autostart", "--no-auto-check-trustdb", "--lock-never",
                                  "--no-default-keyring"] + keyringArguments +
                                 ["--fingerprint", "--list-keys"], checkingKeys: true)
    }

    private func createTestKeys() {
        guard detectedPath != nil, !isTesting, testKeyHome == nil else { return }
        // A short path also leaves room for GnuPG's agent socket names.
        let folder = URL(fileURLWithPath: "/private/tmp")
            .appendingPathComponent("gpgp-test-" + UUID().uuidString)
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false,
                                                     attributes: [.posixPermissions: 0o700])
            // Retain even a failed attempt for inspection; never overwrite an existing keyring.
            testKeyHome = folder.path
            runDiagnostic(arguments: ["--no-options", "--homedir", folder.path,
                                      "--batch", "--no-tty", "--pinentry-mode", "loopback",
                                      "--passphrase", "", "--status-fd", "1",
                                      "--quick-generate-key", "GPGP Test <gpgp-test@example.invalid>",
                                      "default", "default", "1d"],
                          checkingKeys: false, testKeyOperation: true, timeoutSeconds: 60)
        } catch {
            testKeyResult = "Unable to create test folder: \(error.localizedDescription)"
        }
    }

    private func encryptedMailTest() {
        guard let testKeyHome, !isTesting else { return }
        let common = ["--no-options", "--homedir", testKeyHome, "--batch", "--no-tty",
                      "--no-auto-check-trustdb", "--no-auto-key-retrieve"]
        let folder = URL(fileURLWithPath: testKeyHome)
            .appendingPathComponent("encrypted-mail-" + UUID().uuidString)
        let content = SignedMailSample.content()
        let part = folder.appendingPathComponent("content.mime")
        let encrypted = folder.appendingPathComponent("encrypted.asc")
        let extracted = folder.appendingPathComponent("extracted.asc")
        let recovered = folder.appendingPathComponent("recovered.mime")
        let mailURL = folder.appendingPathComponent("encrypted-test.eml")
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false,
                                                     attributes: [.posixPermissions: 0o700])
            try content.write(to: part)
        } catch {
            testKeyResult = "Unable to prepare email sample: \(error.localizedDescription)"
            return
        }
        // This trust override is restricted to our isolated, disposable test identity.
        runDiagnostic(arguments: common + ["--trust-model", "always", "--recipient", "gpgp-test@example.invalid",
                                           "--armor", "--output", encrypted.path, "--encrypt", part.path],
                      checkingKeys: false, testKeyOperation: true, timeoutSeconds: 15) { status, output in
            guard status == 0 else {
                testKeyResult = "Email encryption failed.\n\(output)"
                return
            }
            do {
                let armor = try String(contentsOf: encrypted, encoding: .utf8)
                let boundary = "gpgp_" + UUID().uuidString
                try EncryptedMailSample.assemble(armor: armor, boundary: boundary).write(to: mailURL)
                let payload = try EncryptedMailSample.extract(from: Data(contentsOf: mailURL), boundary: boundary)
                try payload.write(to: extracted)
            } catch {
                testKeyResult = "Encrypted email packaging failed: \(error.localizedDescription)"
                return
            }
            runDiagnostic(arguments: common + ["--pinentry-mode", "loopback", "--passphrase", "",
                                               "--status-fd", "1", "--output", recovered.path,
                                               "--decrypt", extracted.path],
                          checkingKeys: false, testKeyOperation: true, timeoutSeconds: 15) { status, output in
                guard status == 0, output.split(separator: "\n").contains("[GNUPG:] DECRYPTION_OKAY") else {
                    testKeyResult = "Packaged email decryption failed.\n\(output)"
                    return
                }
                do {
                    guard try Data(contentsOf: recovered) == content else {
                        testKeyResult = "FAIL: Decrypted email content differs from the original."
                        return
                    }
                    testKeyResult = "PASS: Encrypted payload extracted from .eml and decrypted.\nPASS: Recovered MIME headers and content match exactly.\nSaved locally (not sent):\n\(mailURL.path)"
                } catch {
                    testKeyResult = "Unable to read recovered email: \(error.localizedDescription)"
                }
            }
        }
    }

    private func signedMailTest() {
        guard let testKeyHome, !isTesting else { return }
        let common = ["--no-options", "--homedir", testKeyHome, "--batch", "--no-tty",
                      "--no-auto-check-trustdb", "--no-auto-key-retrieve"]
        let folder = URL(fileURLWithPath: testKeyHome)
            .appendingPathComponent("mail-test-" + UUID().uuidString)
        let content = SignedMailSample.content()
        let part = folder.appendingPathComponent("content.mime")
        let signature = folder.appendingPathComponent("signature.asc")
        let mailURL = folder.appendingPathComponent("signed-test.eml")
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false,
                                                     attributes: [.posixPermissions: 0o700])
            try content.write(to: part)
        } catch {
            testKeyResult = "Unable to prepare email sample: \(error.localizedDescription)"
            return
        }
        runDiagnostic(arguments: common + ["--pinentry-mode", "loopback", "--passphrase", "",
                                           "--local-user", "gpgp-test@example.invalid", "--armor",
                                           "--digest-algo", "SHA256", "--status-fd", "1",
                                           "--output", signature.path, "--detach-sign", part.path],
                      checkingKeys: false, testKeyOperation: true, timeoutSeconds: 15) { status, output in
            guard status == 0,
                  let record = output.split(separator: "\n").first(where: { $0.hasPrefix("[GNUPG:] SIG_CREATED ") }),
                  let signer = record.split(separator: " ").last else {
                testKeyResult = "Email signing failed.\n\(output)"
                return
            }
            let extractedPart = folder.appendingPathComponent("extracted.mime")
            let extractedSignature = folder.appendingPathComponent("extracted.asc")
            do {
                let armor = try String(contentsOf: signature, encoding: .utf8)
                let boundary = "gpgp_" + UUID().uuidString
                try SignedMailSample.assemble(content: content, signature: armor, boundary: boundary).write(to: mailURL)
                let (recovered, recoveredSignature) = try SignedMailSample.extract(from: Data(contentsOf: mailURL), boundary: boundary)
                guard recovered == content else {
                    testKeyResult = "FAIL: Packaging changed the signed bytes."
                    return
                }
                try recovered.write(to: extractedPart)
                try recoveredSignature.write(to: extractedSignature)
            } catch {
                testKeyResult = "Email packaging failed: \(error.localizedDescription)"
                return
            }
            runDiagnostic(arguments: common + ["--status-fd", "1", "--verify", extractedSignature.path, extractedPart.path],
                          checkingKeys: false, testKeyOperation: true) { status, output in
                let verified = output.split(separator: "\n").contains {
                    let fields = $0.split(separator: " ")
                    return fields.count > 2 && fields[0] == "[GNUPG:]" && fields[1] == "VALIDSIG" && fields[2] == signer
                }
                testKeyResult = status == 0 && verified
                    ? "PASS: Signed email packaged without changing the signed bytes.\nPASS: Signature extracted from .eml verified.\nSaved locally (not sent):\n\(mailURL.path)"
                    : "Packaged email signature verification failed.\n\(output)"
            }
        }
    }

    private func encryptAndDecryptTest() {
        guard let testKeyHome, !isTesting else { return }
        let common = ["--no-options", "--homedir", testKeyHome, "--batch", "--no-tty",
                      "--no-auto-check-trustdb", "--no-auto-key-retrieve"]
        let folder = URL(fileURLWithPath: testKeyHome)
            .appendingPathComponent("encrypt-test-" + UUID().uuidString)
        let message = folder.appendingPathComponent("message.txt")
        let encrypted = folder.appendingPathComponent("message.gpg")
        let decrypted = folder.appendingPathComponent("recovered.txt")
        let original = Data("GPGP encryption test.\r\nA sample with Unicode: café 🔐\r\n".utf8)
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false,
                                                     attributes: [.posixPermissions: 0o700])
            try original.write(to: message)
        } catch {
            testKeyResult = "Unable to prepare sample: \(error.localizedDescription)"
            return
        }
        runDiagnostic(arguments: common + ["--with-colons", "--fingerprint", "--list-keys",
                                           "gpgp-test@example.invalid"],
                      checkingKeys: false, testKeyOperation: true) { status, output in
            guard status == 0,
                  let record = output.split(separator: "\n").first(where: { $0.hasPrefix("fpr:") }) else {
                testKeyResult = "Could not identify the test key.\n\(output)"
                return
            }
            let fields = record.split(separator: ":", omittingEmptySubsequences: false)
            guard fields.count > 9, !fields[9].isEmpty else {
                testKeyResult = "GnuPG returned an incomplete fingerprint."
                return
            }
            let fingerprint = String(fields[9])
            // Trust override applies only to this disposable keyring and explicit fingerprint.
            runDiagnostic(arguments: common + ["--trust-model", "always", "--recipient", fingerprint,
                                               "--status-fd", "1", "--output", encrypted.path,
                                               "--encrypt", message.path],
                          checkingKeys: false, testKeyOperation: true, timeoutSeconds: 15) { status, output in
                guard status == 0, FileManager.default.fileExists(atPath: encrypted.path) else {
                    testKeyResult = "Encryption failed.\n\(output)"
                    return
                }
                runDiagnostic(arguments: common + ["--pinentry-mode", "loopback", "--passphrase", "",
                                                   "--status-fd", "1", "--output", decrypted.path,
                                                   "--decrypt", encrypted.path],
                              checkingKeys: false, testKeyOperation: true, timeoutSeconds: 15) { status, output in
                    let confirmed = output.split(separator: "\n").contains { $0 == "[GNUPG:] DECRYPTION_OKAY" }
                    guard status == 0, confirmed else {
                        testKeyResult = "Decryption failed.\n\(output)"
                        return
                    }
                    do {
                        guard try Data(contentsOf: decrypted) == original else {
                            testKeyResult = "FAIL: Recovered bytes differ from the original sample."
                            return
                        }
                        testKeyResult = "PASS: Sample encrypted and decrypted.\nPASS: Recovered bytes exactly match the original, including Unicode and line endings.\nRecipient: \(fingerprint)\nTest files: \(folder.path)"
                    } catch {
                        testKeyResult = "Unable to read recovered sample: \(error.localizedDescription)"
                    }
                }
            }
        }
    }

    private func signAndVerifyTest() {
        guard let testKeyHome, !isTesting else { return }
        let common = ["--no-options", "--homedir", testKeyHome, "--batch", "--no-tty",
                      "--no-auto-check-trustdb", "--no-auto-key-retrieve"]
        let folder = URL(fileURLWithPath: testKeyHome)
            .appendingPathComponent("sign-test-" + UUID().uuidString)
        let message = folder.appendingPathComponent("message.txt")
        let signature = folder.appendingPathComponent("message.sig")
        let altered = folder.appendingPathComponent("altered.txt")
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false,
                                                     attributes: [.posixPermissions: 0o700])
            try Data("GPGP signing test.\r\nThis is a disposable sample message.\r\n".utf8).write(to: message)
            try Data("GPGP signing test.\r\nThis message has been changed.\r\n".utf8).write(to: altered)
        } catch {
            testKeyResult = "Unable to prepare sample: \(error.localizedDescription)"
            return
        }
        runDiagnostic(arguments: common + ["--with-colons", "--fingerprint", "--list-keys",
                                           "gpgp-test@example.invalid"],
                      checkingKeys: false, testKeyOperation: true) { status, output in
            guard status == 0,
                  let record = output.split(separator: "\n").first(where: { $0.hasPrefix("fpr:") }) else {
                testKeyResult = "Could not identify the test key.\n\(output)"
                return
            }
            let fields = record.split(separator: ":", omittingEmptySubsequences: false)
            guard fields.count > 9, !fields[9].isEmpty else {
                testKeyResult = "GnuPG returned an incomplete fingerprint."
                return
            }
            let fingerprint = String(fields[9])
            runDiagnostic(arguments: common + ["--pinentry-mode", "loopback", "--passphrase", "",
                                               "--local-user", fingerprint, "--status-fd", "1",
                                               "--output", signature.path, "--detach-sign", message.path],
                          checkingKeys: false, testKeyOperation: true, timeoutSeconds: 15) { status, output in
                guard status == 0 else {
                    testKeyResult = "Signing failed.\n\(output)"
                    return
                }
                runDiagnostic(arguments: common + ["--status-fd", "1", "--verify", signature.path, message.path],
                              checkingKeys: false, testKeyOperation: true) { status, output in
                    let validSignature = output.split(separator: "\n").contains {
                        let parts = $0.split(separator: " ")
                        return parts.count > 2 && parts[0] == "[GNUPG:]" && parts[1] == "VALIDSIG"
                            && parts[2] == fingerprint
                    }
                    guard status == 0, validSignature else {
                        testKeyResult = "Verification failed or returned an unexpected signer.\n\(output)"
                        return
                    }
                    runDiagnostic(arguments: common + ["--status-fd", "1", "--verify", signature.path, altered.path],
                                  checkingKeys: false, testKeyOperation: true) { status, output in
                        let rejected = status != 0 && output.contains("[GNUPG:] BADSIG ")
                        testKeyResult = rejected
                            ? "PASS: Sample signed and signature verified.\nPASS: Changed sample rejected.\nSigner: \(fingerprint)\nTest files: \(folder.path)"
                            : "Original signature verified, but changed-message test did not return the expected rejection.\n\(output)"
                    }
                }
            }
        }
    }

    private func runDiagnostic(arguments: [String], checkingKeys: Bool,
                               testKeyOperation: Bool = false, timeoutSeconds: Int = 5,
                               completion: (@MainActor (Int32, String) -> Void)? = nil) {
        guard let detectedPath, !isTesting else { return }
        isTesting = true
        if testKeyOperation { testKeyResult = "Working…" }
        else if checkingKeys { keyResult = "Checking…" } else { versionResult = nil }

        let accessURL = selectedURL ?? URL(fileURLWithPath: detectedPath)
        let hasAccess = accessURL.startAccessingSecurityScopedResource()
        let process = Process()
        // A temporary output file avoids filling a pipe when a keyring is large.
        let outputURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        guard FileManager.default.createFile(atPath: outputURL.path, contents: nil,
                                            attributes: [.posixPermissions: 0o600]),
              let outputHandle = try? FileHandle(forWritingTo: outputURL) else {
            if hasAccess { accessURL.stopAccessingSecurityScopedResource() }
            let message = "Unable to prepare diagnostic output."
            if testKeyOperation { testKeyResult = message }
            else if checkingKeys { keyResult = message } else { versionResult = message }
            isTesting = false
            try? FileManager.default.removeItem(at: outputURL)
            completion?(-1, message)
            return
        }
        process.executableURL = URL(fileURLWithPath: detectedPath)
        process.arguments = arguments
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = outputHandle
        process.standardError = outputHandle
        process.terminationHandler = { finished in
            try? outputHandle.close()
            let data = (try? Data(contentsOf: outputURL)) ?? Data()
            try? FileManager.default.removeItem(at: outputURL)
            let output = String(decoding: data, as: UTF8.self)
            if hasAccess { accessURL.stopAccessingSecurityScopedResource() }
            Task { @MainActor in
                let result = "Exit status: \(finished.terminationStatus)\n" +
                    (output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && checkingKeys && finished.terminationStatus == 0
                     ? "No public keys found." : output)
                if testKeyOperation { testKeyResult = result }
                else if checkingKeys { keyResult = result } else { versionResult = result }
                isTesting = false
                completion?(finished.terminationStatus, output)
            }
        }
        do {
            try process.run()
            // Keep a stalled diagnostic from running indefinitely.
            Task { @MainActor in
                try? await Task.sleep(for: .seconds(timeoutSeconds))
                if process.isRunning { process.terminate() }
            }
        } catch {
            process.terminationHandler = nil
            try? outputHandle.close()
            try? FileManager.default.removeItem(at: outputURL)
            if hasAccess { accessURL.stopAccessingSecurityScopedResource() }
            let error = error as NSError
            let message = "Launch failed: \(error.localizedDescription)\nDomain: \(error.domain)\nCode: \(error.code)\n\(error.userInfo)"
            if testKeyOperation { testKeyResult = message }
            else if checkingKeys { keyResult = message } else { versionResult = message }
            isTesting = false
            completion?(-1, message)
        }
    }
}

#Preview {
    ContentView()
}
