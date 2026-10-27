import Foundation

nonisolated enum SecuredMessageReply {
    static func requireContent(_ data: Data?, error: String?) throws -> Data {
        // Any reported error wins over accompanying bytes. Never treat partial
        // output from a failed/cancelled operation as a secured message.
        if let error {
            throw failure(error.isEmpty ? "GnuPG could not complete the requested protection. Nothing was returned for sending." : error)
        }
        guard let data, !data.isEmpty else {
            throw failure("GnuPG returned no secured message. Nothing was returned for sending.")
        }
        return data
    }
    private static func failure(_ message: String) -> NSError {
        NSError(domain: "com.JimKelley.GPGP.Mail", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
