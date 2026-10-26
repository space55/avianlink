#!/usr/bin/env bash
# Runs every fuzz target for a while (default 60 s each). Needs nightly and
# cargo-fuzz:  rustup toolchain install nightly && cargo install cargo-fuzz
#   scripts/fuzz.sh [seconds-per-target] [target...]
set -euo pipefail
cd "$(dirname "$0")/.."
secs="${1:-60}"
shift || true
targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
    targets=($(cargo +nightly fuzz list))
fi
for t in "${targets[@]}"; do
    printf '\n==> fuzz %s for %ss\n' "$t" "$secs"
    cargo +nightly fuzz run "$t" -- -max_total_time="$secs" -max_len=2048 -timeout=10
done
