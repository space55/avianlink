#!/usr/bin/env bash
# Builds target/Avianlink.xcframework (docs/ffi.md §4): iOS device, iOS
# simulator (arm64 + x86_64) and macOS (arm64 + x86_64), each a static
# library with avianlink.h and a module map so Swift can `import Avianlink`.
set -euo pipefail
cd "$(dirname "$0")/.."

TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin)
rustup target add "${TARGETS[@]}" >/dev/null
for t in "${TARGETS[@]}"; do
    cargo build -p avianlink-ffi --release --target "$t" --quiet
done

out=target/xcframework
rm -rf "$out" target/Avianlink.xcframework
mkdir -p "$out/headers" "$out/ios-sim" "$out/macos"
cp crates/avianlink-ffi/include/avianlink.h "$out/headers/"
cat > "$out/headers/module.modulemap" <<'MAP'
module Avianlink {
    header "avianlink.h"
    export *
}
MAP

lib=libavianlink_ffi.a
lipo -create target/aarch64-apple-ios-sim/release/$lib target/x86_64-apple-ios/release/$lib \
    -output "$out/ios-sim/$lib"
lipo -create target/aarch64-apple-darwin/release/$lib target/x86_64-apple-darwin/release/$lib \
    -output "$out/macos/$lib"

fw=target/Avianlink.xcframework
if xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/$lib -headers "$out/headers" \
    -library "$out/ios-sim/$lib" -headers "$out/headers" \
    -library "$out/macos/$lib" -headers "$out/headers" \
    -output "$fw" >/dev/null 2>&1; then
    echo "$fw (xcodebuild)"
    exit 0
fi

# xcodebuild unavailable or broken (e.g. Command Line Tools only): assemble
# the bundle directly. The format is a directory per slice plus Info.plist.
echo "xcodebuild -create-xcframework failed; assembling $fw by hand" >&2
rm -rf "$fw"
slice() { # id lib platform variant archs...
    local id=$1 src=$2 platform=$3 variant=$4
    shift 4
    mkdir -p "$fw/$id"
    cp "$src" "$fw/$id/$lib"
    cp -R "$out/headers" "$fw/$id/Headers"
    printf '\t\t<dict>\n'
    printf '\t\t\t<key>BinaryPath</key>\n\t\t\t<string>%s</string>\n' "$lib"
    printf '\t\t\t<key>HeadersPath</key>\n\t\t\t<string>Headers</string>\n'
    printf '\t\t\t<key>LibraryIdentifier</key>\n\t\t\t<string>%s</string>\n' "$id"
    printf '\t\t\t<key>LibraryPath</key>\n\t\t\t<string>%s</string>\n' "$lib"
    printf '\t\t\t<key>SupportedArchitectures</key>\n\t\t\t<array>\n'
    for a in "$@"; do printf '\t\t\t\t<string>%s</string>\n' "$a"; done
    printf '\t\t\t</array>\n'
    printf '\t\t\t<key>SupportedPlatform</key>\n\t\t\t<string>%s</string>\n' "$platform"
    if [ -n "$variant" ]; then
        printf '\t\t\t<key>SupportedPlatformVariant</key>\n\t\t\t<string>%s</string>\n' "$variant"
    fi
    printf '\t\t</dict>\n'
}
mkdir -p "$fw"
{
    cat <<'HEAD'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AvailableLibraries</key>
	<array>
HEAD
    slice ios-arm64 target/aarch64-apple-ios/release/$lib ios "" arm64
    slice ios-arm64_x86_64-simulator "$out/ios-sim/$lib" ios simulator arm64 x86_64
    slice macos-arm64_x86_64 "$out/macos/$lib" macos "" arm64 x86_64
    cat <<'TAIL'
	</array>
	<key>CFBundlePackageType</key>
	<string>XFWK</string>
	<key>XCFrameworkFormatVersion</key>
	<string>1.0</string>
</dict>
</plist>
TAIL
} > "$fw/Info.plist"
plutil -lint "$fw/Info.plist" >/dev/null
echo "$fw (assembled)"
