#!/usr/bin/env bash
# Gate for `apps/desktop`. Every commit that touches the app must pass this.
#
# Deliberately self-contained and separate from `scripts/ci.sh`, which is the
# library's gate (see apps/desktop/docs/decisions.md DA-003). This script never
# touches `crates/`: Rust lints run with `--no-deps` so a warning in the
# library cannot fail the app's build, and vice versa.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
APP="$ROOT/apps/desktop"

step() { printf '\n==> %s\n' "$*"; }
fail() { printf '\nFAILED: %s\n' "$*" >&2; exit 1; }

# Skip the browser-driven suite where no browser is installed (a fresh
# container, say). Everything else is mandatory.
SKIP_E2E="${SKIP_E2E:-0}"

step "node dependencies"
if [ ! -d "$APP/node_modules" ]; then
    (cd "$APP" && npm ci)
fi

step "cargo fmt --check"
cargo fmt -p avianlink-desktop -- --check

step "cargo clippy (app only, warnings are errors)"
cargo clippy -p avianlink-desktop --all-targets --locked --no-deps -- -D warnings

step "cargo test"
# This also regenerates src/lib/ipc/bindings.ts via ts-rs.
cargo test -p avianlink-desktop --locked

step "generated bindings are current"
# `cargo test` rewrites the bindings; if that changed the file, the committed
# copy was stale. The frontend jobs typecheck against the committed copy
# without a Rust toolchain, so it has to be right (DA-007).
BINDINGS="apps/desktop/src/lib/ipc/bindings.ts"
if ! git diff --quiet -- "$BINDINGS"; then
    git --no-pager diff --stat -- "$BINDINGS"
    fail "$BINDINGS is out of date; commit the regenerated file"
fi

step "prettier --check"
(cd "$APP" && npm run format:check)

step "eslint"
(cd "$APP" && npm run lint)

step "svelte-check and tsc"
(cd "$APP" && npm run check)

step "vitest"
(cd "$APP" && npm run test)

step "vite build"
(cd "$APP" && npm run build)

if [ "$SKIP_E2E" = "1" ]; then
    step "playwright (skipped: SKIP_E2E=1)"
else
    step "playwright"
    (cd "$APP" && npm run test:e2e)
fi

step "ok"
