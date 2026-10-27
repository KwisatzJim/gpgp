//
//  MessageSecurityViewController.swift
//  GPGPMail
//
//  Created by Jim Kelley on 10/25/26.
//

import MailKit

class MessageSecurityViewController: MEExtensionViewController {
    var details = "No signature information available."

    override func loadView() {
        let label = NSTextField(wrappingLabelWithString: details)
        label.isSelectable = true
        label.translatesAutoresizingMaskIntoConstraints = false
        view = NSView(frame: NSRect(x: 0, y: 0, width: 440, height: 260))
        view.addSubview(label)
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            label.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            label.topAnchor.constraint(equalTo: view.topAnchor, constant: 20),
            label.bottomAnchor.constraint(lessThanOrEqualTo: view.bottomAnchor, constant: -20)
        ])
        preferredContentSize = NSSize(width: 440, height: 260)
    }

}
