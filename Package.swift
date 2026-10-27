// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "GPGPCore",
    platforms: [.macOS(.v13)],
    products: [.library(name: "GPGPCore", targets: ["GPGPCore"])],
    targets: [
        .target(name: "GPGPCore", path: "GPGP", exclude: [
            "GPGP", "GPGPMail", "GPGP.xcodeproj", "GPGPTests", "GPGPUITests", "Configuration",
            "GPGPBridge/main.swift", "GPGPBridge/BridgeListener.swift"
        ], sources: ["Shared", "GPGPBridge"]),
        .testTarget(name: "GPGPCoreTests", dependencies: ["GPGPCore"], path: "Tests")
    ],
    swiftLanguageModes: [.v5]
)
