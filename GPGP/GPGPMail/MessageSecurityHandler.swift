//
//  MessageSecurityHandler.swift
//  GPGPMail
//
//  Created by Jim Kelley on 10/25/26.
//

import MailKit
import OSLog

class MessageSecurityHandler: NSObject, MEMessageSecurityHandler {

    static let shared = MessageSecurityHandler()
    private static let log = Logger(subsystem: "com.JimKelley.GPGP.GPGPMail", category: "MessageSecurity")

    // MARK: - Encoding Messages

    func getEncodingStatus(for message: MEMessage, composeContext: MEComposeContext, completionHandler: @escaping (MEOutgoingMessageEncodingStatus) -> Void) {
        guard let sender = message.fromAddress.addressString else {
            completionHandler(MEOutgoingMessageEncodingStatus(canSign: false, canEncrypt: false, securityError: nil, addressesFailingEncryption: []))
            return
        }
        let recipients = message.allRecipientAddresses
        let hasBCC = !message.bccAddresses.isEmpty
        let addresses = recipients.map { $0.addressString ?? "" }
        SecurityBridgeRequest<(Bool, Bool)>(seconds: 20) { result in
            switch result {
            case .success(let availability):
                let canEncrypt = availability.1 && !hasBCC
                completionHandler(MEOutgoingMessageEncodingStatus(canSign: availability.0, canEncrypt: canEncrypt,
                    securityError: nil, addressesFailingEncryption: canEncrypt ? [] : recipients))
            case .failure(let error):
                completionHandler(MEOutgoingMessageEncodingStatus(canSign: false, canEncrypt: false,
                    securityError: error, addressesFailingEncryption: recipients))
            }
        }.start { proxy, done in
            proxy.encodingStatus(sender: sender, recipients: addresses) { canSign, canEncrypt, error in
                if let error { done(.failure(SecurityBridgeRequest<Data>.error(error))) }
                else { done(.success((canSign, canEncrypt))) }
            }
        }
    }

    func encode(_ message: MEMessage, composeContext: MEComposeContext, completionHandler: @escaping (MEMessageEncodingResult) -> Void) {
        let shouldSign = composeContext.shouldSign
        let shouldEncrypt = composeContext.shouldEncrypt
        Self.log.notice("Encode requested: state=\(message.state.rawValue), sign=\(shouldSign), encrypt=\(shouldEncrypt)")
        if message.state == .draft {
            // Development policy: draft saves remain unencrypted and unsigned.
            // Message security is applied to the separate sending invocation.
            Self.log.notice("Draft save: returning without message encoding")
            completionHandler(MEMessageEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: nil))
            return
        }
        guard shouldSign || shouldEncrypt else {
            completionHandler(MEMessageEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: nil))
            return
        }
        func fail(_ error: Error) {
            completionHandler(MEMessageEncodingResult(encodedMessage: nil, signingError: shouldSign ? error : nil,
                                                      encryptionError: shouldEncrypt ? error : nil))
        }
        guard !shouldEncrypt || message.bccAddresses.isEmpty else {
            fail(SecurityBridgeRequest<Data>.error("Encrypted Bcc delivery is not supported yet. Remove Bcc recipients or send separate encrypted messages."))
            return
        }
        guard let raw = message.rawData, let sender = message.fromAddress.addressString else {
            fail(SecurityBridgeRequest<Data>.error("Mail did not supply the data and sender required for message security."))
            return
        }
        let addresses = message.allRecipientAddresses.map { $0.addressString ?? "" }
        SecurityBridgeRequest<Data>(seconds: 210) { result in
            switch result {
            case .success(let data):
                do {
                    let transported = try MailKitEncryptionTransport.prepare(data, encrypted: shouldEncrypt)
                    Self.log.notice("Returning encoded message: bytes=\(transported.count), signed=\(shouldSign), encrypted=\(shouldEncrypt)")
                    let encoded = MEEncodedOutgoingMessage(rawData: transported, isSigned: shouldSign, isEncrypted: shouldEncrypt)
                    completionHandler(MEMessageEncodingResult(encodedMessage: encoded, signingError: nil, encryptionError: nil))
                } catch { fail(error) }
            case .failure(let error): fail(error)
            }
        }.start { proxy, done in
            let reply: (Data?, String?) -> Void = { encoded, error in
                do { done(.success(try SecuredMessageReply.requireContent(encoded, error: error))) }
                catch { done(.failure(error)) }
            }
            if shouldEncrypt {
                proxy.encryptMessage(raw, sender: sender, recipients: addresses, sign: shouldSign, withReply: reply)
            } else {
                proxy.signMessage(raw, sender: sender, withReply: reply)
            }
        }
    }

    // MARK: - Decoding Messages

    func decodedMessage(forMessageData data: Data) -> MEDecodedMessage? {
        guard data.count <= 2 * 1024 * 1024 else { return nil }
        // Recognize headers in both Mail's LF storage format and wire CRLF.
        // The helper restores canonical MIME bytes before checking signatures.
        let prefix = String(decoding: data.prefix(65536), as: UTF8.self)
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\n", with: "\r\n")
        guard let end = prefix.range(of: "\r\n\r\n") else { return nil }
        let headers = String(prefix[..<end.lowerBound])
        let encrypted = headers.range(of: #"(?im)^Content-Type:\s*multipart/encrypted\s*;"#, options: .regularExpression) != nil
            && headers.range(of: "application/pgp-encrypted", options: .caseInsensitive) != nil
        let signed = headers.range(of: #"(?im)^Content-Type:\s*multipart/signed\s*;"#, options: .regularExpression) != nil
            && headers.range(of: "application/pgp-signature", options: .caseInsensitive) != nil
        guard encrypted || signed else { return nil }
        Self.log.notice("Incoming PGP/MIME decoding requested: encrypted=\(encrypted)")
        let reply = encrypted ? IncomingVerificationClient.decrypt(data) : IncomingVerificationClient.verify(data)
        if let error = reply.encryptionError ?? reply.error {
            Self.log.notice("Incoming security operation failed; returning error-report MIME")
            return DecodingFailurePresentation.make(details: error, encrypted: encrypted)
        }
        guard reply.decoded != nil else {
            return DecodingFailurePresentation.make(details: "The helper did not return decoded message content.", encrypted: encrypted)
        }
        let signers: [MEMessageSigner]
        let details: String
        if let fingerprint = reply.fingerprint, fingerprint.count == 40,
           fingerprint.allSatisfy({ $0.isHexDigit }), reply.error == nil, reply.encryptionError == nil, reply.decoded != nil {
            details = (encrypted ? "Message decrypted.\n\n" : "") + "OpenPGP signature verified against a local public key.\n\nSigning fingerprint:\n\(fingerprint)\n\nThis validates the signed message content. It does not independently establish the sender’s identity or authenticate outer From and Subject headers."
            signers = [MEMessageSigner(emailAddresses: [], signatureLabel: "OpenPGP signature verified", context: Data(details.utf8))]
            Self.log.notice("Incoming signature verified")
        } else if encrypted, reply.encryptionError == nil, reply.decoded != nil, reply.error == nil {
            details = "Message decrypted and encryption integrity checked.\n\nNo digital signature was present. Encryption alone does not establish who sent the message."
            signers = []
            Self.log.notice("Incoming encrypted message decoded without a signature")
        } else {
            return DecodingFailurePresentation.make(details: "The helper did not return a valid signing fingerprint.", encrypted: encrypted)
        }
        let information = MEMessageSecurityInformation(signers: signers, isEncrypted: encrypted,
            signingError: nil, encryptionError: nil,
            shouldBlockRemoteContent: true, localizedRemoteContentBlockingReason: "GPGP does not authorize remote content in secured messages.")
        let displayed = reply.decoded.map { MailKitEncryptionTransport.decoded($0) }
        return MEDecodedMessage(data: displayed, securityInformation: information, context: Data(details.utf8))
    }

    func extensionViewController(signers messageSigners: [MEMessageSigner]) -> MEExtensionViewController? {
        let details = messageSigners.compactMap { String(data: $0.context, encoding: .utf8) }.joined(separator: "\n\n")
        return detailsController(details.isEmpty ? "No verified signer information available." : details)
    }

    func extensionViewController(messageContext context: Data) -> MEExtensionViewController? {
        detailsController(String(data: context, encoding: .utf8) ?? "No signature details available.")
    }

    func primaryActionClicked(forMessageContext context: Data, completionHandler: @escaping (MEExtensionViewController?) -> Void) {
        completionHandler(extensionViewController(messageContext: context))
    }

    private func detailsController(_ details: String) -> MEExtensionViewController {
        let controller = MessageSecurityViewController(nibName: nil, bundle: nil)
        controller.details = details
        return controller
    }
}
