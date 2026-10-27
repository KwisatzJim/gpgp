import Foundation

nonisolated enum GnuPGRuntime {
    static let systemPaths = ["/opt/homebrew/bin/gpg", "/usr/local/bin/gpg", "/usr/local/MacGPG2/bin/gpg"]
    static func bundledRoot(startingAt location: URL) -> URL? {
        var cursor = location.standardizedFileURL
        for _ in 0..<12 {
            if cursor.pathExtension == "app" {
                let runtime = cursor.appendingPathComponent("Contents/Resources/GnuPG")
                if FileManager.default.fileExists(atPath: runtime.appendingPathComponent("runtime-manifest.json").path) { return runtime }
                return nil
            }
            let parent = cursor.deletingLastPathComponent()
            if parent == cursor { break }
            cursor = parent
        }
        return nil
    }
    static var bundled: URL? {
        bundledRoot(startingAt: Bundle.main.executableURL ?? Bundle.main.bundleURL)
    }
    static var candidatePaths: [String] {
        // A packaged runtime must stand on its own. Do not silently mask a
        // broken bundle with a different Homebrew installation.
        if let bundled { return [bundled.appendingPathComponent("bin/gpg").path] }
        return systemPaths
    }
    static func isBundled(_ executable: String) -> Bool {
        let root = URL(fileURLWithPath: executable).deletingLastPathComponent().deletingLastPathComponent()
        return FileManager.default.fileExists(atPath: root.appendingPathComponent("runtime-manifest.json").path)
    }
    static func pinentry(for executable: String) -> String? {
        let candidates = isBundled(executable)
            ? [URL(fileURLWithPath: executable).deletingLastPathComponent().appendingPathComponent("pinentry-mac").path]
            : ["/opt/homebrew/bin/pinentry-mac", "/usr/local/bin/pinentry-mac"]
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }
}
