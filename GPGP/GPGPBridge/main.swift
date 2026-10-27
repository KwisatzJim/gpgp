//
//  main.swift
//  GPGPBridge
//
//  Created by Jim Kelley on 10/26/26.
//

import Foundation

struct ProbeReply: Encodable {
    let protocolVersion: Int
    let reply: String
    let nonce: String
}

// This first helper accepts only a harmless probe. No command execution API.
let arguments = Array(CommandLine.arguments.dropFirst())
if arguments == ["--agent"] {
    let delegate = BridgeListener()
    let listener = NSXPCListener(machServiceName: "com.JimKelley.GPGP.bridge")
    listener.setConnectionCodeSigningRequirement("anchor apple generic and certificate leaf[subject.OU] = \"MV65BFBFT7\" and (identifier \"com.JimKelley.GPGP\" or identifier \"com.JimKelley.GPGP.GPGPMail\")")
    listener.delegate = delegate
    listener.resume()
    withExtendedLifetime((listener, delegate)) { RunLoop.current.run() }
    exit(0)
}
guard arguments.count == 2, arguments[0] == "--ping",
      UUID(uuidString: arguments[1]) != nil else {
    FileHandle.standardError.write(Data("Usage: GPGPBridge --ping <UUID>\n".utf8))
    exit(64)
}
do {
    let data = try JSONEncoder().encode(ProbeReply(protocolVersion: 1, reply: "pong", nonce: arguments[1]))
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([10]))
} catch {
    FileHandle.standardError.write(Data("Unable to encode probe response.\n".utf8))
    exit(1)
}
