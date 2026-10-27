import Foundation

/// A deliberately narrow fixture builder, not a general incoming-mail parser.
enum SignedMailSample {
    static func content() -> Data {
        let body = Data("GPGP signed email test.\r\nUnicode sample: café 🔐\r\n".utf8)
        let encoded = body.base64EncodedString(options: [.lineLength76Characters, .endLineWithCarriageReturn, .endLineWithLineFeed])
        return Data(("Content-Type: text/plain; charset=utf-8\r\n" +
                     "Content-Transfer-Encoding: base64\r\n\r\n" + encoded + "\r\n").utf8)
    }

    static func assemble(content: Data, signature: String, boundary: String) -> Data {
        let armor = signature.replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\n", with: "\r\n")
        let headers = ["From: GPGP Test <gpgp-test@example.invalid>",
                       "To: GPGP Test <gpgp-test@example.invalid>",
                       "Subject: GPGP local signing test",
                       "Date: Mon, 26 Oct 2026 12:00:00 +0000",
                       "MIME-Version: 1.0",
                       "Content-Type: multipart/signed;",
                       " protocol=\"application/pgp-signature\"; micalg=pgp-sha256;",
                       " boundary=\"\(boundary)\"", "", "--\(boundary)", ""]
        var mail = Data(headers.joined(separator: "\r\n").utf8)
        mail.append(content)
        mail.append(Data(("\r\n--\(boundary)\r\n" +
                          "Content-Type: application/pgp-signature; name=\"signature.asc\"\r\n" +
                          "Content-Transfer-Encoding: 7bit\r\n" +
                          "Content-Disposition: attachment; filename=\"signature.asc\"\r\n\r\n" +
                          armor + "\r\n--\(boundary)--\r\n").utf8))
        return mail
    }

    static func extract(from mail: Data, boundary: String) throws -> (Data, Data) {
        let text = String(decoding: mail, as: UTF8.self)
        let parts = text.components(separatedBy: "--\(boundary)\r\n")
        guard parts.count == 3, parts[1].hasSuffix("\r\n"),
              let headerEnd = parts[2].range(of: "\r\n\r\n"),
              let closing = parts[2].range(of: "\r\n--\(boundary)--\r\n") else {
            throw CocoaError(.fileReadCorruptFile)
        }
        return (Data(Data(parts[1].utf8).dropLast(2)),
                Data(parts[2][headerEnd.upperBound..<closing.lowerBound].utf8))
    }
}
