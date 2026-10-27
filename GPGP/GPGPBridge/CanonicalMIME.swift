import Foundation

enum CanonicalMIME {
    /// Mail may store MIME using LF. OpenPGP/MIME signatures cover canonical
    /// CRLF data. Preserve existing CRLF and all other bytes, including a final
    /// newline's presence or absence; only supply CR before a bare LF.
    static func lineEndings(_ raw: Data) -> Data {
        var canonical = Data()
        canonical.reserveCapacity(raw.count)
        var previous: UInt8?
        for byte in raw {
            if byte == 10 && previous != 13 { canonical.append(13) }
            canonical.append(byte)
            previous = byte
        }
        return canonical
    }
}
