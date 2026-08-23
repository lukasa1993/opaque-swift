// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OpaqueSwift",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(name: "OpaqueSwift", targets: ["OpaqueSwift"]),
    ],
    targets: [
        .binaryTarget(
            name: "COpaque",
            path: "Artifacts/COpaque.xcframework"
        ),
        .target(
            name: "OpaqueSwift",
            dependencies: ["COpaque"]
        ),
        .testTarget(
            name: "OpaqueSwiftTests",
            dependencies: ["OpaqueSwift"]
        ),
    ]
)
