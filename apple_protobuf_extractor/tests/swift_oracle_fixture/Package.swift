// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "oracle",
    dependencies: [
        .package(url: "https://github.com/apple/swift-protobuf.git", exact: "1.30.0")
    ],
    targets: [
        .executableTarget(
            name: "oracle",
            dependencies: [
                .product(name: "SwiftProtobuf", package: "swift-protobuf")
            ],
            linkerSettings: [
                .unsafeFlags(["-Xlinker", "-fixup_chains"])
            ]
        )
    ]
)
