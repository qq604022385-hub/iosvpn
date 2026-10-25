// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "FortiCore", platforms: [.iOS(.v16), .macOS(.v13)],
    products: [.library(name: "FortiCore", targets: ["FortiCore"])],
    targets: [.target(name: "FortiCore", path: "Core", resources: [.process("Resources")]),
              .testTarget(name: "FortiCoreTests", dependencies: ["FortiCore"], path: "Tests")])