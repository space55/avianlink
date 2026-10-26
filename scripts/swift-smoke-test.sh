#!/usr/bin/env bash
# Builds the XCFramework, then compiles and runs
# crates/avianlink-ffi/examples/swift/main.swift against its macOS slice via a
# SwiftPM binaryTarget (which also validates the bundle's Info.plist).
set -euo pipefail
cd "$(dirname "$0")/.."

scripts/build-xcframework.sh
pkg=target/swift-smoke
rm -rf "$pkg"
mkdir -p "$pkg/Sources/Smoke"
cp crates/avianlink-ffi/examples/swift/main.swift "$pkg/Sources/Smoke/"
ln -s ../Avianlink.xcframework "$pkg/Avianlink.xcframework"
cat > "$pkg/Package.swift" <<'SWIFT'
// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Smoke",
    platforms: [.macOS(.v12)],
    targets: [
        .binaryTarget(name: "Avianlink", path: "Avianlink.xcframework"),
        .executableTarget(name: "Smoke", dependencies: ["Avianlink"]),
    ]
)
SWIFT
swift run --package-path "$pkg" -c release Smoke
