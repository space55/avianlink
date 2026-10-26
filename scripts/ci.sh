#!/usr/bin/env bash
# Local/CI gate. Every commit must pass this.
set -euo pipefail
cd "$(dirname "$0")/.."

EMBEDDED_TARGETS=(thumbv7em-none-eabihf aarch64-apple-ios)
# The library's crates. Named explicitly because the workspace also holds
# the desktop app (apps/desktop), which has its own gate.
LIB_PKGS=(-p avianlink-core -p avianlink-sim -p avianlink-udp -p avianlink-cli -p avianlink-ffi)

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

step "ok"
