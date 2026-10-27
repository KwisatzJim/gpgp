//
//  MailExtension.swift
//  GPGPMail
//
//  Created by Jim Kelley on 10/25/26.
//

import MailKit

class MailExtension: NSObject, MEExtension {
    func handler(for session: MEComposeSession) -> MEComposeSessionHandler {
        ComposeSessionHandler()
    }



    func handlerForMessageSecurity() -> MEMessageSecurityHandler {
        // Use a shared instance for all messages, since there's
        // no state associated with the security handler.
        return MessageSecurityHandler.shared
    }

}
