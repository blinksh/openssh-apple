// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "openssh-apple",
    platforms: [.macOS("11")],
    dependencies: [
        .package(url: "https://github.com/yury/FMake", from : "0.0.15"),
    //    .package(path: "../FMake")
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "openssh-apple",
            dependencies: ["FMake"]),
    ]
)
