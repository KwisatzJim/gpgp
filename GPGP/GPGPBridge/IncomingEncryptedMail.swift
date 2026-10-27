import Foundation

enum IncomingEncryptedMail {
    struct Parts {
        let encrypted: Data
        let transport: [String]
        func restore(_ entity: Data) -> Data {
            var result = Data(((transport + ["MIME-Version: 1.0"]).joined(separator: "\r\n") + "\r\n").utf8)
            result.append(entity)
            return result
        }
    }

    static func parse(_ raw: Data) throws -> Parts {
        guard raw.count <= 2 * 1024 * 1024, let text = String(data: CanonicalMIME.lineEndings(raw), encoding: .utf8),
              let split = text.range(of: "\r\n\r\n") else { throw error("Unsupported or incomplete encrypted-email format.") }
        let headers = try parseHeaders(String(text[..<split.lowerBound]))
        let types = headers.filter { name($0) == "content-type" }
        guard types.count == 1, let type = types.first,
              value(type).split(separator: ";").first?.trimmingCharacters(in: .whitespaces).lowercased() == "multipart/encrypted",
              parameter("protocol", in: value(type))?.lowercased() == "application/pgp-encrypted",
              let boundary = parameter("boundary", in: value(type)), !boundary.isEmpty, boundary.count <= 70,
              boundary.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45, 95].contains($0) }) else {
            throw error("Unsupported PGP/MIME encryption headers.")
        }
        let lines = text[split.upperBound...].components(separatedBy: "\r\n")
        let delimiter = "--" + boundary
        let markers = lines.enumerated().filter { $0.element == delimiter || $0.element == delimiter + "--" }
        guard markers.count == 3, markers[0].element == delimiter, markers[1].element == delimiter,
              markers[2].element == delimiter + "--" else { throw error("Encrypted email must contain exactly two complete MIME parts.") }
        let control = lines[(markers[0].offset + 1)..<markers[1].offset].joined(separator: "\r\n")
        let payload = lines[(markers[1].offset + 1)..<markers[2].offset].joined(separator: "\r\n")
        guard let firstSplit = control.range(of: "\r\n\r\n"), let secondSplit = payload.range(of: "\r\n\r\n") else {
            throw error("Incomplete encrypted-email MIME parts.")
        }
        let firstHeaders = try parseHeaders(String(control[..<firstSplit.lowerBound]))
        let secondHeaders = try parseHeaders(String(payload[..<secondSplit.lowerBound]))
        func hasType(_ headers: [String], _ expected: String) -> Bool {
            let types = headers.filter { name($0) == "content-type" }
            return types.count == 1 && value(types[0]).split(separator: ";").first?.trimmingCharacters(in: .whitespaces).lowercased() == expected
        }
        let encodings = secondHeaders.filter { name($0) == "content-transfer-encoding" }
        guard hasType(firstHeaders, "application/pgp-encrypted"),
              String(control[firstSplit.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines) == "Version: 1",
              hasType(secondHeaders, "application/octet-stream"), encodings.count <= 1,
              encodings.first.map({ value($0).lowercased() == "7bit" }) ?? true else {
            throw error("Unsupported encryption control part or transfer encoding.")
        }
        let armor = String(payload[secondSplit.upperBound...])
        guard armor.hasPrefix("-----BEGIN PGP MESSAGE-----\r\n"), armor.contains("\r\n-----END PGP MESSAGE-----"),
              armor.utf8.allSatisfy({ $0 < 128 }) else { throw error("Missing armored encrypted payload.") }
        return Parts(encrypted: Data(armor.utf8), transport: headers.filter { !name($0).hasPrefix("content-") && name($0) != "mime-version" })
    }

    static func entityType(_ entity: Data) -> String? {
        guard let text = String(data: entity.prefix(65536), encoding: .utf8), let end = text.range(of: "\r\n\r\n"),
              let headers = try? parseHeaders(String(text[..<end.lowerBound])) else { return nil }
        let types = headers.filter { name($0) == "content-type" }
        guard types.count == 1 else { return nil }
        return value(types[0]).split(separator: ";").first?.trimmingCharacters(in: .whitespaces).lowercased()
    }
    private static func parseHeaders(_ text: String) throws -> [String] {
        var headers: [String] = []
        for line in text.components(separatedBy: "\r\n") {
            guard !line.contains("\0") else { throw error("Invalid MIME header.") }
            if line.hasPrefix(" ") || line.hasPrefix("\t") {
                guard !headers.isEmpty else { throw error("Invalid folded MIME header.") }
                headers[headers.count - 1] += "\r\n" + line
            } else {
                guard let colon = line.firstIndex(of: ":"), colon > line.startIndex else { throw error("Invalid MIME header.") }
                headers.append(line)
            }
        }
        return headers
    }
    private static func name(_ header: String) -> String { String(header.prefix(while: { $0 != ":" })).lowercased() }
    private static func value(_ header: String) -> String {
        String(header.drop(while: { $0 != ":" }).dropFirst()).replacingOccurrences(of: "\r\n", with: "").trimmingCharacters(in: .whitespaces)
    }
    private static func parameter(_ name: String, in value: String) -> String? {
        let pattern = "(?:^|;)\\s*" + name + "\\s*=\\s*(?:\"([^\"]*)\"|([^;\\s]+))"
        guard let expression = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return nil }
        let matches = expression.matches(in: value, range: NSRange(value.startIndex..., in: value))
        guard matches.count == 1 else { return nil }
        let match = matches[0]
        return Range(match.range(at: match.range(at: 1).location != NSNotFound ? 1 : 2), in: value).map { String(value[$0]) }
    }
    private static func error(_ message: String) -> NSError {
        NSError(domain: "com.JimKelley.GPGP.Decryption", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
