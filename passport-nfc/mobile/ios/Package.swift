// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "VaultysPassport",
    platforms: [.iOS(.v15)],
    products: [.library(name: "VaultysPassport", targets: ["VaultysPassport"])],
    targets: [
        .binaryTarget(name: "VaultysPassportEngine", path: "VaultysPassportEngine.xcframework"),
        .target(name: "VaultysPassport", dependencies: ["VaultysPassportEngine"])
    ]
)
