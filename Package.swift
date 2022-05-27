// swift-tools-version: 5.4

import PackageDescription

let package = Package(
    name: "BIP39",
    platforms: [
        .macOS(.v10_15), .iOS(.v11)
    ],
    products: [
        .library(name: "BIP39", targets: ["BIP39"]),
    ],
    dependencies: [
    ],
    targets: [
        .target(
            name: "BIP39", dependencies: []),
        .testTarget(
            name: "BIP39Tests", dependencies: ["BIP39"]),
    ]
)
