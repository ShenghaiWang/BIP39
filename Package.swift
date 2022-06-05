// swift-tools-version: 5.4

import PackageDescription

let package = Package(
    name: "BIP39",
    platforms: [
        .macOS(.v10_12), .iOS(.v9), .tvOS(.v9), .watchOS(.v2)
    ],
    products: [
        .library(name: "BIP39", targets: ["BIP39"]),
    ],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMajor(from: "1.5.1"))
    ],
    targets: [
        .target(
            name: "BIP39", dependencies: ["CryptoSwift"]),
        .testTarget(
            name: "BIP39Tests", dependencies: ["BIP39"]),
    ]
)
