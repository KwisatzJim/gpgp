import Foundation

struct IncomingVerificationReply: Sendable {
    let decoded: Data?
    let fingerprint: String?
    let error: String?
    let isEncrypted: Bool
    let encryptionError: String?

    init(decoded: Data?, fingerprint: String?, error: String?, isEncrypted: Bool = false, encryptionError: String? = nil) {
        self.decoded = decoded
        self.fingerprint = fingerprint
        self.error = error
        self.isEncrypted = isEncrypted
        self.encryptionError = encryptionError
    }
}

private final class VerificationReplyBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: IncomingVerificationReply?
    func store(_ value: IncomingVerificationReply) {
        lock.lock(); defer { lock.unlock() }
        self.value = value
    }
    func read() -> IncomingVerificationReply? {
        lock.lock(); defer { lock.unlock() }
        return value
    }
}

enum IncomingVerificationClient {
    static func verify(_ raw: Data) -> IncomingVerificationReply {
        perform(raw, decrypt: false)
    }

    static func decrypt(_ raw: Data) -> IncomingVerificationReply {
        perform(raw, decrypt: true)
    }

    private static func perform(_ raw: Data, decrypt: Bool) -> IncomingVerificationReply {
        // MailKit's decoder is synchronous. XPC replies arrive on a separate
        // queue; never dispatch the reply to the main actor that is waiting here.
        let ready = DispatchSemaphore(value: 0)
        let box = VerificationReplyBox()
        func failure(_ message: String) -> IncomingVerificationReply {
            IncomingVerificationReply(decoded: nil, fingerprint: nil, error: decrypt ? nil : message,
                                      isEncrypted: decrypt, encryptionError: decrypt ? message : nil)
        }
        SecurityBridgeRequest<IncomingVerificationReply>(seconds: decrypt ? 175 : 15) { result in
            switch result {
            case .success(let reply): box.store(reply)
            case .failure(let error): box.store(failure(error.localizedDescription))
            }
            ready.signal()
        }.start { proxy, done in
            if decrypt {
                proxy.decryptMessage(raw) { decoded, fingerprint, signingError, encryptionError in
                    done(.success(IncomingVerificationReply(decoded: decoded, fingerprint: fingerprint, error: signingError,
                                                           isEncrypted: true, encryptionError: encryptionError)))
                }
            } else {
            proxy.verifyMessage(raw) { decoded, fingerprint, error in
                done(.success(IncomingVerificationReply(decoded: decoded, fingerprint: fingerprint, error: error)))
            }
            }
        }
        guard ready.wait(timeout: .now() + (decrypt ? 177 : 17)) == .success, let reply = box.read() else {
            return failure(decrypt ? "Message decryption timed out." : "Signature verification timed out.")
        }
        return reply
    }
}
