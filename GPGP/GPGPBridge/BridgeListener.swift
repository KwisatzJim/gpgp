import Foundation


final class BridgeListener: NSObject, NSXPCListenerDelegate, GPGPBridgeProtocol {
    private let signingQueue = DispatchQueue(label: "com.JimKelley.GPGP.bridge.signing")
    private let verificationQueue = DispatchQueue(label: "com.JimKelley.GPGP.bridge.verification", attributes: .concurrent)
    private let statusQueue = DispatchQueue(label: "com.JimKelley.GPGP.bridge.status")
    private let decryptionQueue = DispatchQueue(label: "com.JimKelley.GPGP.bridge.decryption")
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard connection.effectiveUserIdentifier == geteuid() else { return false }
        connection.exportedInterface = NSXPCInterface(with: GPGPBridgeProtocol.self)
        connection.exportedObject = self
        connection.resume()
        return true
    }

    func ping(_ nonce: String, withReply reply: @escaping (String) -> Void) {
        reply(UUID(uuidString: nonce) == nil ? "invalid-request" : nonce)
    }

    func gnuPGVersion(withReply reply: @escaping (String) -> Void) {
        DispatchQueue.global(qos: .utility).async {
            reply(GnuPGVersionProbe.run())
        }
    }

    func testSigning(withReply reply: @escaping (String) -> Void) {
        signingQueue.async { reply(GnuPGSigningProbe.run()) }
    }

    func testEncryption(withReply reply: @escaping (String) -> Void) {
        signingQueue.async { reply(GnuPGEncryptionProbe.run()) }
    }

    func signingKey(for sender: String, withReply reply: @escaping (String?, String?) -> Void) {
        statusQueue.async {
            let result = PersonalSigningIdentity.lookup(sender: sender)
            reply(result.0, result.1)
        }
    }

    func encodingStatus(sender: String, recipients: [String], withReply reply: @escaping (Bool, Bool, String?) -> Void) {
        guard recipients.count <= 100 else { reply(false, false, "Too many recipients for this version."); return }
        statusQueue.async {
            let signing = PersonalSigningIdentity.lookup(sender: sender)
            guard signing.0 != nil else { reply(false, false, signing.1); return }
            let encryption = PersonalMessageEncryptor.recipientKeys(recipients)
            reply(true, encryption.0 != nil, nil)
        }
    }

    func encryptMessage(_ raw: Data, sender: String, recipients: [String], sign: Bool, withReply reply: @escaping (Data?, String?) -> Void) {
        guard raw.count <= 2 * 1024 * 1024, recipients.count <= 100 else {
            reply(nil, "This version supports MIME messages up to 2 MB and 100 recipients."); return
        }
        signingQueue.async {
            let result = PersonalMessageEncryptor.encode(raw, sender: sender, recipients: recipients, sign: sign)
            reply(result.0, result.1)
        }
    }

    func signMessage(_ raw: Data, sender: String, withReply reply: @escaping (Data?, String?) -> Void) {
        guard raw.count <= 2 * 1024 * 1024 else { reply(nil, "Signing is limited to 2 MB in this version."); return }
        signingQueue.async {
            let result = PersonalMessageSigner.sign(raw, sender: sender)
            reply(result.0, result.1)
        }
    }

    func verifyMessage(_ raw: Data, withReply reply: @escaping (Data?, String?, String?) -> Void) {
        guard raw.count <= 2 * 1024 * 1024 else { reply(nil, nil, "Signature verification is currently limited to 2 MB."); return }
        verificationQueue.async {
            let result = IncomingSignatureVerifier.verify(raw)
            reply(result.0, result.1, result.2)
        }
    }

    func decryptMessage(_ raw: Data, withReply reply: @escaping (Data?, String?, String?, String?) -> Void) {
        guard raw.count <= 2 * 1024 * 1024 else { reply(nil, nil, nil, "Encrypted-email decoding is currently limited to 2 MB."); return }
        decryptionQueue.async {
            let result = IncomingMessageDecryptor.decrypt(raw)
            reply(result.0, result.1, result.2, result.3)
        }
    }
}
