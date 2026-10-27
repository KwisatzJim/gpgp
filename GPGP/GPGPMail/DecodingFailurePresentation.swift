import MailKit

@MainActor enum DecodingFailurePresentation {
    static func make(details: String, encrypted: Bool) -> MEDecodedMessage {
        let title = encrypted ? "GPGP could not decrypt this message." : "GPGP could not verify this message."
        let report = title + "\r\n\r\n" + details +
            "\r\n\r\nThis is an error report, not decrypted or verified message content. Your original message has not been changed."
        let encoded = Data(report.utf8).base64EncodedString(options: [.lineLength76Characters, .endLineWithCarriageReturn, .endLineWithLineFeed])
        let mime = "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" + encoded + "\r\n"
        // Mail 27.0.1 crashes in CertificateBanner when handling our decode
        // failures. Do not invoke that banner path or expose rejected plaintext.
        // isEncrypted describes the original message, not a successful decrypt.
        let information = MEMessageSecurityInformation(signers: [], isEncrypted: encrypted,
            signingError: nil, encryptionError: nil, shouldBlockRemoteContent: true,
            localizedRemoteContentBlockingReason: "GPGP could not complete message security processing.")
        return MEDecodedMessage(data: MailKitEncryptionTransport.decoded(Data(mime.utf8)), securityInformation: information, context: Data(report.utf8))
    }
}
