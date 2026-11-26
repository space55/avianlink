#!/usr/bin/env bash
# Local/CI gate. Every commit must pass this.
set -euo pipefail
cd "$(dirname "$0")/.."

EMBEDDED_TARGETS=(thumbv7em-none-eabihf aarch64-apple-ios)
# The library's crates, named explicitly so that local experiments added to
# the workspace don't join the gate.
LIB_PKGS=(-p avianlink-core -p avianlink-sim -p avianlink-udp -p avianlink-cli -p avianlink-ffi -p avianlink-relay)

step() { printf '\n==> %s\n' "$*"; }

step "rustup targets"
installed=$(rustup target list --installed)
for t in "${EMBEDDED_TARGETS[@]}"; do
    if ! grep -qx "$t" <<<"$installed"; then
        echo "missing target $t; run: rustup target add $t" >&2
        exit 1
    fi
done

step "cargo fmt --check"
cargo fmt "${LIB_PKGS[@]}" -- --check
cargo fmt --manifest-path fuzz/Cargo.toml -- --check

step "cargo clippy (library crates, host, all targets)"
cargo clippy "${LIB_PKGS[@]}" --all-targets --locked -- -D warnings

step "cargo test (library crates)"
cargo test "${LIB_PKGS[@]}" --locked

for t in "${EMBEDDED_TARGETS[@]}"; do
    step "avianlink-core: build + clippy for $t (no default features)"
    cargo build -p avianlink-core --no-default-features --target "$t" --locked
    cargo clippy -p avianlink-core --no-default-features --target "$t" --locked -- -D warnings
done

step "avianlink.h is up to date (cbindgen)"
if ! command -v cbindgen >/dev/null; then
    echo "cbindgen not found; run: cargo install cbindgen" >&2
    exit 1
fi
fresh=$(mktemp)
trap 'rm -f "$fresh"' EXIT
(cd crates/avianlink-ffi && cbindgen --quiet --config cbindgen.toml --crate avianlink-ffi --output "$fresh")
if ! diff -u crates/avianlink-ffi/include/avianlink.h "$fresh"; then
    echo "header is stale; regenerate with: (cd crates/avianlink-ffi && cbindgen --config cbindgen.toml --crate avianlink-ffi --output include/avianlink.h)" >&2
    exit 1
fi

step "C example against the static library"
scripts/c-example.sh

if [ "$(uname)" = Darwin ]; then
    step "avianlink-ffi: build for aarch64-apple-ios"
    cargo build -p avianlink-ffi --target aarch64-apple-ios --locked
fi

step "Wireshark dissector (skipped without tshark)"
scripts/wireshark-check.sh

step "shell scripts (skipped without shellcheck)"
if command -v shellcheck >/dev/null; then
    shellcheck deploy/install-relay.sh scripts/*.sh
fi

step "ok"
