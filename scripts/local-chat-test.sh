#!/usr/bin/env bash
# Two `avianlink chat` processes exchange messages through `udp-impair`
# on loopback.
# Usage: scripts/local-chat-test.sh [PROFILE] [MESSAGES] [TIMEOUT_S] [INTERVAL_S]
# PROFILE is any simrun scenario (default bursty_loss: disaster_cellular
# without outages). Exits non-zero unless every message arrives.
set -euo pipefail
cd "$(dirname "$0")/.."
profile="${1:-bursty_loss}"; n="${2:-10}"; timeout="${3:-180}"; interval="${4:-0}"
cargo build -q --release -p avianlink-cli -p avianlink-sim --bins
bin=target/release
work="$(mktemp -d)"; trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$work"' EXIT
for who in alice bob; do "$bin/avianlink" init "$work/$who" > "$work/$who.id"; done
key() { awk '/^address:/ { print $2 }' "$work/$1.id"; }
pa=17001; pb=17002; ha=17101; hb=17102
"$bin/udp-impair" --a 127.0.0.1:$pa --b 127.0.0.1:$pb --to-a 127.0.0.1:$ha --to-b 127.0.0.1:$hb \
  --profile "$profile" 2> "$work/impair.log" &
mkfifo "$work/alice.in" "$work/bob.in"
"$bin/avianlink" chat "$work/alice" --bind 127.0.0.1:$ha --peer "$(key bob)@127.0.0.1:$pa" \
  --profile "$profile" < "$work/alice.in" > "$work/alice.out" 2>&1 &
"$bin/avianlink" chat "$work/bob" --bind 127.0.0.1:$hb --peer "$(key alice)@127.0.0.1:$pb" \
  --profile "$profile" < "$work/bob.in" > "$work/bob.out" 2>&1 &
exec 3> "$work/alice.in" 4> "$work/bob.in"
for i in $(seq 1 "$n"); do
  echo "hello bob, this is alice, message $i of $n; $(printf 'pad%.0s' $(seq 1 40))" >&3
  echo "hi alice, bob here, message $i of $n; $(printf 'pad%.0s' $(seq 1 40))" >&4
  sleep "$interval"
done
start=$SECONDS
while (( SECONDS - start < timeout )); do
  ra=$(grep -c '^<< ' "$work/alice.out" || true); rb=$(grep -c '^<< ' "$work/bob.out" || true)
  da=$(grep -c 'delivered #' "$work/alice.out" || true); db=$(grep -c 'delivered #' "$work/bob.out" || true)
  if (( ra == n && rb == n && da == n && db == n )); then break; fi
  sleep 1
done
echo "/status" >&3; echo "/status" >&4; sleep 1
echo "/quit" >&3; echo "/quit" >&4; sleep 1
echo "== alice"; cat "$work/alice.out"; echo "== bob"; cat "$work/bob.out"; echo "== udp-impair"; cat "$work/impair.log"
echo "profile $profile: alice received $ra/$n (delivered $da), bob received $rb/$n (delivered $db) in $((SECONDS - start)) s"
(( ra == n && rb == n && da == n && db == n ))
