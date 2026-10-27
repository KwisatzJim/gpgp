import Foundation

enum MailKitEncryptionTransport {
    /// MailKit's message viewer uses LF separators as well as its encrypted
    /// outgoing-message parser. Preserve every other byte, including encoded
    /// body data; crypto verification has already finished in the helper.
    static func decoded(_ raw: Data) -> Data {
        let bytes = Array(raw)
        var native = Data()
        native.reserveCapacity(bytes.count)
        for index in bytes.indices {
            if bytes[index] == 13, index + 1 < bytes.count, bytes[index + 1] == 10 { continue }
            native.append(bytes[index])
        }
        return native
    }
    /// Use Mail's native LF representation for both signed and encrypted sends.
    /// Canonical CRLF is restored by incoming MIME processing before signature
    /// verification. Do not change the ciphertext or inner MIME content here.
    static func prepare(_ raw: Data, encrypted: Bool = true) throws -> Data {
        guard let text = String(data: raw, encoding: .utf8) else { throw failure() }
        let native = text.replacingOccurrences(of: "\r\n", with: "\n")
        guard let split = native.range(of: "\n\n") else { throw failure() }
        let headers = String(native[..<split.lowerBound])
        let body = String(native[split.upperBound...])
        let contentTypes = headers.components(separatedBy: "\n").filter { $0.lowercased().hasPrefix("content-type:") }
        let mediaType = encrypted ? "multipart/encrypted" : "multipart/signed"
        let armorType = encrypted ? "PGP MESSAGE" : "PGP SIGNATURE"
        guard contentTypes.count == 1, contentTypes[0].lowercased().contains(mediaType),
              body.contains("-----BEGIN \(armorType)-----\n"), body.contains("\n-----END \(armorType)-----") else {
            throw failure()
        }
        return Data(native.utf8)
    }

    private static func failure() -> NSError {
        NSError(domain: "com.JimKelley.GPGP.Mail", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "The secured message is incomplete. No message was returned for sending."])
    }
}
