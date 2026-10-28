#!/usr/bin/env bash
# Checks tools/wireshark/avianlink.lua against a freshly generated capture:
# no Lua errors, every packet decoded, every relay checksum valid, and every
# upload's computed receipt hash matched by a relay RECEIPT.
set -euo pipefail
cd "$(dirname "$0")/.."

TSHARK=$(command -v tshark || true)
[ -z "$TSHARK" ] && [ -x /Applications/Wireshark.app/Contents/MacOS/tshark ] &&
    TSHARK=/Applications/Wireshark.app/Contents/MacOS/tshark
if [ -z "$TSHARK" ]; then
    echo "tshark not found; skipping the Wireshark dissector check"
    exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cargo run -q -p avianlink-relay --example sample_pcap -- "$work/sample.pcap" 2>/dev/null
# -n: no name resolution (it can stall); stdin closed (tshark may wait on it).
ts() { "$TSHARK" -n -X lua_script:tools/wireshark/avianlink.lua -r "$work/sample.pcap" "$@" </dev/null 2>&1; }

fail() { echo "wireshark-check: $*" >&2; exit 1; }
[ "$(ts -V | grep -c 'Lua Error' || true)" = 0 ] || fail "Lua errors"
[ "$(ts -Y '!avianlink' | wc -l | tr -d ' ')" = 0 ] || fail "packets not decoded"
[ "$(ts -Y 'avianlink.relay.check_ok == 0' | wc -l | tr -d ' ')" = 0 ] || fail "bad checksums"
ts -Y 'avianlink.receipt_hash && ip.dst == 10.0.0.9' -T fields -e avianlink.receipt_hash | sort -u >"$work/up"
ts -Y 'avianlink.kind == 0x19' -T fields -e avianlink.relay.hash | tr ',' '\n' | sort -u >"$work/rc"
ups=$(wc -l <"$work/up" | tr -d ' ')
matched=$(comm -12 "$work/up" "$work/rc" | wc -l | tr -d ' ')
[ "$ups" -gt 0 ] && [ "$matched" = "$ups" ] || fail "only $matched of $ups uploads matched a RECEIPT"
echo "wireshark-check: ok ($(ts | wc -l | tr -d ' ') packets, $ups uploads matched to receipts)"
