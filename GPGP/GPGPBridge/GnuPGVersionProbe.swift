import Foundation

enum GnuPGVersionProbe {
    static func run() -> String {
        let candidates = GnuPGRuntime.candidatePaths
        guard let path = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            return "GnuPG not found by the background helper."
        }
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = ["--no-options", "--version"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
            let timeout = DispatchWorkItem {
                if process.isRunning { process.terminate() }
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + 5, execute: timeout)
            defer { timeout.cancel() }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            let output = String(decoding: data, as: UTF8.self)
            guard process.terminationStatus == 0,
                  let firstLine = output.split(separator: "\n").first,
                  firstLine.hasPrefix("gpg (GnuPG) ") else {
                return "GnuPG version test failed (exit \(process.terminationStatus)).\n\(output.prefix(400))"
            }
            return "PASS: Background helper ran \(firstLine).\nExecutable: \(path)"
        } catch {
            return "Helper could not launch GnuPG: \(error.localizedDescription)"
        }
    }
}
