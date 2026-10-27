import Foundation

enum IncomingSignedMail {
    struct Parts {
        let content: Data
        let signature: Data
        let decoded: Data
        let digest: String
    }

    static func parse(_ raw: Data) throws -> Parts {
        guard raw.count <= 2 * 1024 * 1024, let text = String(data: CanonicalMIME.lineEndings(raw), encoding: .utf8),
              let separator = text.range(of: "\r\n\r\n") else { throw failure("Unsupported or incomplete signed-email format.") }
        let outer = try headers(String(text[..<separator.lowerBound]))
        guard let type = single("content-type", in: outer),
              type.split(separator: ";").first?.trimmingCharacters(in: .whitespaces).lowercased() == "multipart/signed",
              parameter("protocol", in: type)?.lowercased() == "application/pgp-signature",
              let algorithm = parameter("micalg", in: type)?.lowercased(),
              let digest = ["pgp-sha256": "8", "pgp-sha384": "9", "pgp-sha512": "10"][algorithm],
              let boundary = parameter("boundary", in: type), !boundary.isEmpty, boundary.count <= 70,
              boundary.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45, 95].contains($0) }) else {
            throw failure("This verifier supports SHA-256, SHA-384, and SHA-512 PGP/MIME signatures.")
        }
        let body = String(text[separator.upperBound...])
        let delimiter = "--" + boundary
        let lines = body.components(separatedBy: "\r\n")
        let markers = lines.enumerated().filter { $0.element == delimiter || $0.element == delimiter + "--" }
        guard markers.count == 3, markers[0].element == delimiter, markers[1].element == delimiter,
              markers[2].element == delimiter + "--" else { throw failure("Signed email must contain exactly two complete MIME parts.") }
        // Joining lines omits only the CRLF belonging to the following boundary.
        let content = lines[(markers[0].offset + 1)..<markers[1].offset].joined(separator: "\r\n")
        let signaturePart = lines[(markers[1].offset + 1)..<markers[2].offset].joined(separator: "\r\n")
        guard let contentSplit = content.range(of: "\r\n\r\n"),
              let signatureSplit = signaturePart.range(of: "\r\n\r\n") else { throw failure("Signed email has incomplete MIME parts.") }
        let contentHeaders = try headers(String(content[..<contentSplit.lowerBound]))
        let signatureHeaders = try headers(String(signaturePart[..<signatureSplit.lowerBound]))
        guard ["text/plain", "text/html", "multipart/mixed", "multipart/alternative", "multipart/related"].contains(single("content-type", in: contentHeaders)?.split(separator: ";").first?.trimmingCharacters(in: .whitespaces).lowercased() ?? ""),
              single("content-type", in: signatureHeaders)?.split(separator: ";").first?.trimmingCharacters(in: .whitespaces).lowercased() == "application/pgp-signature",
              [nil, "7bit"].contains(single("content-transfer-encoding", in: signatureHeaders)?.lowercased()),
              content.utf8.allSatisfy({ $0 < 128 }) else { throw failure("Unsupported signed content or signature encoding.") }
        let signature = String(signaturePart[signatureSplit.upperBound...])
        guard signature.hasPrefix("-----BEGIN PGP SIGNATURE-----\r\n"),
              signature.contains("\r\n-----END PGP SIGNATURE-----") else { throw failure("Missing armored OpenPGP signature.") }
        let transport = outer.filter { !$0.name.hasPrefix("content-") && $0.name != "mime-version" }.map(\.raw)
        let prefix = (transport + ["MIME-Version: 1.0"]).joined(separator: "\r\n") + "\r\n"
        return Parts(content: Data(content.utf8), signature: Data(signature.utf8), decoded: Data((prefix + content).utf8), digest: digest)
    }

    private struct Header { let name: String; let value: String; let raw: String }
    private static func headers(_ text: String) throws -> [Header] {
        var unfolded: [String] = []
        for line in text.components(separatedBy: "\r\n") {
            guard !line.contains("\0") else { throw failure("Invalid MIME header.") }
            if line.hasPrefix(" ") || line.hasPrefix("\t") {
                guard !unfolded.isEmpty else { throw failure("Invalid folded MIME header.") }
                unfolded[unfolded.count - 1] += "\r\n" + line
            } else { unfolded.append(line) }
        }
        return try unfolded.map { raw in
            guard let colon = raw.firstIndex(of: ":"), colon > raw.startIndex else { throw failure("Invalid MIME header.") }
            return Header(name: raw[..<colon].lowercased(), value: String(raw[raw.index(after: colon)...])
                .replacingOccurrences(of: "\r\n", with: "").trimmingCharacters(in: .whitespaces), raw: raw)
        }
    }
    private static func single(_ name: String, in headers: [Header]) -> String? {
        let found = headers.filter { $0.name == name }
        return found.count == 1 ? found[0].value : nil
    }
    private static func parameter(_ name: String, in value: String) -> String? {
        let pattern = "(?:^|;)\\s*" + name + "\\s*=\\s*(?:\"([^\"]*)\"|([^;\\s]+))"
        guard let expression = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return nil }
        let matches = expression.matches(in: value, range: NSRange(value.startIndex..., in: value))
        guard matches.count == 1 else { return nil }
        let match = matches[0]
        let range = match.range(at: match.range(at: 1).location != NSNotFound ? 1 : 2)
        return Range(range, in: value).map { String(value[$0]) }
    }
    private static func failure(_ message: String) -> NSError {
        NSError(domain: "com.JimKelley.GPGP.Verification", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
