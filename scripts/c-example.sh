#!/usr/bin/env bash
# Builds the static library, compiles crates/avianlink-ffi/examples/c/loopback.c
# against the checked-in header, and runs it.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build -p avianlink-ffi --release --quiet
out="target/c-example"
mkdir -p "$out"
# shellcheck disable=SC2046 # the Linux-only flags are meant to split into two
cc -std=c99 -Wall -Wextra -Werror -pedantic \
    -I crates/avianlink-ffi/include \
    crates/avianlink-ffi/examples/c/loopback.c \
    target/release/libavianlink_ffi.a \
    -lm $( [ "$(uname)" = Linux ] && echo "-lpthread -ldl" ) \
    -o "$out/loopback"
"$out/loopback"
# The header must also be valid C++ (cpp_compat).
echo '#include "avianlink.h"' | c++ -std=c++11 -Wall -Werror -fsyntax-only \
    -I crates/avianlink-ffi/include -x c++ -
