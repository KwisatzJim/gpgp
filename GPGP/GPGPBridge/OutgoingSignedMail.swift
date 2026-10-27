import Foundation

enum OutgoingSignedMail {
    struct Prepared {
        let headers: [String]
        let content: Data
        let boundary: String
    }

    static func prepare(_ raw: Data) throws -> Prepared {
        guard raw.count <= 2 * 1024 * 1024, let text = String(data: raw, encoding: .utf8), !text.contains("\0") else {
            throw failure("GPGP supports UTF-8 MIME messages up to 2 MB.")
        }
        let canonical = text.replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n").replacingOccurrences(of: "\n", with: "\r\n")
        guard let separator = canonical.range(of: "\r\n\r\n") else { throw failure("Mail did not supply complete message headers.") }
        var headers: [String] = []
        for line in canonical[..<separator.lowerBound].components(separatedBy: "\r\n") {
            if line.hasPrefix(" ") || line.hasPrefix("\t") {
                guard !headers.isEmpty else { throw failure("Invalid folded message header.") }
                headers[headers.count - 1] += "\r\n" + line
            } else {
                guard let colon = line.firstIndex(of: ":"), colon != line.startIndex else { throw failure("Invalid message header.") }
                headers.append(line)
            }
        }
        func name(_ header: String) -> String { String(header.prefix(while: { $0 != ":" })).lowercased() }
        func value(_ header: String) -> String {
            String(header.drop(while: { $0 != ":" }).dropFirst())
                .replacingOccurrences(of: "\r\n", with: "").trimmingCharacters(in: .whitespaces)
        }
        let contentTypes = headers.filter { name($0) == "content-type" }
        let encodings = headers.filter { name($0) == "content-transfer-encoding" }
        guard contentTypes.count <= 1, encodings.count <= 1,
              headers.filter({ name($0) == "from" }).count == 1 else { throw failure("Ambiguous message headers.") }
        let contentType = contentTypes.first.map(value) ?? "text/plain; charset=us-ascii"
        let mediaType = contentType.split(separator: ";").first?.trimmingCharacters(in: .whitespaces).lowercased() ?? ""
        let multipart = ["multipart/mixed", "multipart/alternative", "multipart/related"].contains(mediaType)
        guard multipart || ["text/plain", "text/html"].contains(mediaType) else {
            throw failure("Unsupported message format. Use plain text, HTML, or standard MIME attachments.")
        }
        let encoding = encodings.first.map(value)?.lowercased() ?? "7bit"
        let body = String(canonical[separator.upperBound...])
        var mimeHeaders = headers.filter { name($0).hasPrefix("content-") && name($0) != "content-transfer-encoding" }
        if contentTypes.isEmpty { mimeHeaders.insert("Content-Type: " + contentType, at: 0) }
        let encodedBody: String
        if multipart {
            // Preserve the complete MIME tree, including base64 attachments.
            // Encoding a multipart container itself as base64 is invalid MIME.
            guard ["7bit", "8bit"].contains(encoding), body.utf8.allSatisfy({ $0 < 128 }) else {
                throw failure("Attachments must use standard 7-bit MIME encoding. Try removing the attachment or using plain text.")
            }
            mimeHeaders.append("Content-Transfer-Encoding: 7bit")
            encodedBody = body
        } else {
        switch encoding {
        case "7bit", "8bit":
            guard encoding != "7bit" || body.utf8.allSatisfy({ $0 < 128 }) else {
                throw failure("Message contains non-ASCII text declared as 7-bit data.")
            }
            mimeHeaders.append("Content-Transfer-Encoding: base64")
            encodedBody = Data(body.utf8).base64EncodedString(options: [.lineLength76Characters, .endLineWithCarriageReturn, .endLineWithLineFeed]) + "\r\n"
        case "base64", "quoted-printable":
            guard body.utf8.allSatisfy({ $0 < 128 }) else { throw failure("Invalid encoded text content.") }
            mimeHeaders.append("Content-Transfer-Encoding: " + encoding)
            encodedBody = body.components(separatedBy: "\r\n").map { line in
                var bytes = Array(line.utf8)
                while bytes.last == 32 || bytes.last == 9 { bytes.removeLast() }
                return String(decoding: bytes, as: UTF8.self)
            }.joined(separator: "\r\n")
        default: throw failure("Unsupported text transfer encoding: \(encoding).")
        }
        }
        let content = Data((mimeHeaders.joined(separator: "\r\n") + "\r\n\r\n" + encodedBody).utf8)
        let outer = headers.filter { !name($0).hasPrefix("content-") && !["mime-version", "bcc", "resent-bcc"].contains(name($0)) }
        return Prepared(headers: outer, content: content, boundary: "gpgp_" + UUID().uuidString)
    }

    static func assemble(_ prepared: Prepared, signature: String) -> Data {
        let armor = signature.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\n", with: "\r\n")
        let headers = prepared.headers + ["MIME-Version: 1.0", "Content-Type: multipart/signed;",
            " protocol=\"application/pgp-signature\"; micalg=pgp-sha256;", " boundary=\"\(prepared.boundary)\""]
        var output = Data((headers.joined(separator: "\r\n") + "\r\n\r\n--\(prepared.boundary)\r\n").utf8)
        output.append(prepared.content)
        let signatureHeaders = ["Content-Type: application/pgp-signature; name=\"signature.asc\"",
            "Content-Transfer-Encoding: 7bit", "Content-Disposition: attachment; filename=\"signature.asc\""]
        output.append(Data(("\r\n--\(prepared.boundary)\r\n" + signatureHeaders.joined(separator: "\r\n") +
                           "\r\n\r\n" + armor + "\r\n--\(prepared.boundary)--\r\n").utf8))
        return output
    }

    static func failure(_ message: String) -> NSError {
        NSError(domain: "com.JimKelley.GPGP.Signing", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
