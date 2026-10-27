import Foundation

@objc(GPGPBridgePing) protocol GPGPBridgeProtocol {
    func ping(_ nonce: String, withReply reply: @escaping (String) -> Void)
    func gnuPGVersion(withReply reply: @escaping (String) -> Void)
    func testSigning(withReply reply: @escaping (String) -> Void)
    func testEncryption(withReply reply: @escaping (String) -> Void)
    func signingKey(for sender: String, withReply reply: @escaping (String?, String?) -> Void)
    func signMessage(_ raw: Data, sender: String, withReply reply: @escaping (Data?, String?) -> Void)
    func verifyMessage(_ raw: Data, withReply reply: @escaping (Data?, String?, String?) -> Void)
    func encodingStatus(sender: String, recipients: [String], withReply reply: @escaping (Bool, Bool, String?) -> Void)
    func encryptMessage(_ raw: Data, sender: String, recipients: [String], sign: Bool, withReply reply: @escaping (Data?, String?) -> Void)
    func decryptMessage(_ raw: Data, withReply reply: @escaping (Data?, String?, String?, String?) -> Void)
}
