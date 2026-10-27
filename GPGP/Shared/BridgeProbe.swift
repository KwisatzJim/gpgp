import Foundation

nonisolated enum BridgeProbe {
    private struct Reply: Decodable {
        let protocolVersion: Int
        let reply: String
        let nonce: String
    }

    static func run(executable: URL) -> String {
        let nonce = UUID().uuidString
        do {
            // JSON is a stdout protocol. Runtime warnings on stderr must not
            // contaminate it; retain them separately for actionable diagnostics.
            let result = try KeyringCatalog.command(executable.path, ["--ping", nonce], timeout: 5)
            guard result.status == 0 else {
                return "Bundled helper failed (exit \(result.status)).\n" + result.error
            }
            let reply: Reply
            do { reply = try JSONDecoder().decode(Reply.self, from: Data(result.output.utf8)) }
            catch {
                return "Bundled helper returned an invalid diagnostic reply (\(result.output.utf8.count) output bytes).\nOutput: \(result.output.prefix(400))\nDiagnostics: \(result.error.prefix(400))\nUse Connection → Test Background Connection to check Mail’s running service."
            }
            guard reply.protocolVersion == 1, reply.reply == "pong", reply.nonce == nonce else {
                return "FAIL: Bundled helper returned an unexpected response."
            }
            return "PASS: Bundled helper launched and returned the matching reply."
                + (result.error.isEmpty ? "" : "\nHelper diagnostics: " + result.error)
        } catch {
            return "Bundled helper test could not run: \(error.localizedDescription)\nUse Connection → Test Background Connection to check Mail’s running service."
        }
    }
}
