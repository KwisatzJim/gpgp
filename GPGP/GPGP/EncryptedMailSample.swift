import Foundation

/// Builds and reads only our own two-part encrypted email fixture.
enum EncryptedMailSample {
    static func assemble(armor: String, boundary: String) -> Data {
        let normalized = armor.replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\n", with: "\r\n")
        let lines = [
            "From: GPGP Test <gpgp-test@example.invalid>",
            "To: GPGP Test <gpgp-test@example.invalid>",
            "Subject: GPGP local encryption test",
            "Date: Mon, 26 Oct 2026 12:00:00 +0000",
            "MIME-Version: 1.0",
            "Content-Type: multipart/encrypted;",
            " protocol=\"application/pgp-encrypted\";",
            " boundary=\"\(boundary)\"", "",
            "--\(boundary)", "Content-Type: application/pgp-encrypted", "",
            "Version: 1", "",
            "--\(boundary)",
            "Content-Type: application/octet-stream; name=\"encrypted.asc\"",
            "Content-Transfer-Encoding: 7bit",
            "Content-Disposition: inline; filename=\"encrypted.asc\"", "",
            normalized, "--\(boundary)--", ""
        ]
        return Data(lines.joined(separator: "\r\n").utf8)
    }

    static func extract(from mail: Data, boundary: String) throws -> Data {
        let text = String(decoding: mail, as: UTF8.self)
        let parts = text.components(separatedBy: "--\(boundary)\r\n")
        guard parts.count == 3,
              parts[1] == "Content-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\r\n",
              let headers = parts[2].range(of: "\r\n\r\n"),
              let closing = parts[2].range(of: "\r\n--\(boundary)--\r\n"),
              headers.upperBound <= closing.lowerBound else {
            throw CocoaError(.fileReadCorruptFile)
        }
        return Data(parts[2][headers.upperBound..<closing.lowerBound].utf8)
    }
}
