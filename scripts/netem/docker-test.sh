#!/usr/bin/env bash
# Phase 6 acceptance test in Docker: alice ↔ router (tc netem) ↔ bob.
#
#   scripts/netem/docker-test.sh [PROFILE] [MESSAGES] [INTERVAL_S] [TIMEOUT_S]
#
# alice and bob sit on separate networks and reach each other only through
# a router container that applies scripts/netem/PROFILE.sh (real tc netem,
# both directions, shared outages) on both interfaces. Each runs
# `avianlink chat --profile PROFILE`. Exits non-zero unless every message
# is received and acknowledged on both sides. Defaults: disaster_cellular,
# 20 messages each way, one every 30 s, 30 min timeout.
set -euo pipefail
cd "$(dirname "$0")/../.."
profile="${1:-disaster_cellular}"; n="${2:-20}"; interval="${3:-30}"; timeout="${4:-1800}"
img=avianlink-netem:local
nets=(avl-a avl-b); boxes=(avl-alice avl-router avl-bob)

cleanup() {
  docker rm -f "${boxes[@]}" >/dev/null 2>&1 || true
  docker network rm "${nets[@]}" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

echo "== building Linux binaries"
docker run --rm -v "$PWD":/src -w /src -e CARGO_TARGET_DIR=/src/target/docker \
  -v "${CARGO_HOME:-$HOME/.cargo}/registry":/usr/local/cargo/registry \
  rust:1.92-slim-bookworm cargo build -q --release -p avianlink-cli
docker build -q -t "$img" scripts/netem/docker >/dev/null

echo "== topology"
# Plain bridge networks: Docker's --internal ones drop routed traffic.
# alice and bob still reach each other only via the router (their only
# route to the other subnet).
docker network create --subnet 10.77.1.0/24 avl-a >/dev/null
docker network create --subnet 10.77.2.0/24 avl-b >/dev/null
run() { # name net ip
  docker run -d --name "$1" --network "$2" --ip "$3" --cap-add NET_ADMIN \
    --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv4.conf.all.rp_filter=0 \
    --sysctl net.ipv4.conf.default.rp_filter=0 \
    -v "$PWD/target/docker/release:/bin/avl:ro" -v "$PWD/scripts/netem:/netem:ro" \
    "$img" sleep infinity >/dev/null
}
run avl-router avl-a 10.77.1.2
docker network connect --ip 10.77.2.2 avl-b avl-router
run avl-alice avl-a 10.77.1.10
run avl-bob avl-b 10.77.2.10
docker exec avl-alice ip route add 10.77.2.0/24 via 10.77.1.2
docker exec avl-bob ip route add 10.77.1.0/24 via 10.77.2.2
devs=$(docker exec avl-router sh -c "ip -o -4 addr show | awk '\$4 ~ /^10\\.77\\./ { print \$2 }' | tr '\n' ' '")
echo "router interfaces: $devs"
docker exec avl-alice ping -c2 -W2 10.77.2.10 >/dev/null \
  || { echo "alice cannot reach bob through the router" >&2; exit 1; }
echo "alice -> router -> bob: reachable"

echo "== netem $profile on router ($devs)"
docker exec -d avl-router sh -c "/netem/$profile.sh $devs > /netem.log 2>&1"
sleep 1
docker exec avl-router tc qdisc show

echo "== peers"
for who in alice bob; do docker exec "avl-$who" /bin/avl/avianlink init /data | tee "/tmp/avl-$who.id"; done
key() { awk '/^address:/ { print $2 }' "/tmp/avl-$1.id"; }
start_chat() { # who peer peer_ip
  docker exec "avl-$1" sh -c "mkfifo /in && (sleep infinity > /in &) && \
    (/bin/avl/avianlink chat /data --bind 0.0.0.0:7000 --peer $(key "$2")@$3:7000 \
      --profile $profile < /in > /out 2>&1 &)"
}
start_chat alice bob 10.77.2.10
start_chat bob alice 10.77.1.10
say() { docker exec "avl-$1" sh -c "echo '$2' > /in"; }
count() { docker exec "avl-$1" sh -c "grep -c '$2' /out || true"; }

echo "== exchanging $n messages each way, one every ${interval}s"
start=$SECONDS
for i in $(seq 1 "$n"); do
  say alice "alice -> bob, message $i of $n, sent at $(date +%T); $(printf 'x%.0s' $(seq 1 150))"
  say bob "bob -> alice, message $i of $n, sent at $(date +%T); $(printf 'y%.0s' $(seq 1 150))"
  sleep "$interval"
done
while (( SECONDS - start < timeout )); do
  ra=$(count alice '^<< '); rb=$(count bob '^<< ')
  da=$(count alice 'delivered #'); db=$(count bob 'delivered #')
  printf '\r  t=%4ss  alice got %s/%s (acked %s)  bob got %s/%s (acked %s)  ' \
    $((SECONDS - start)) "$ra" "$n" "$da" "$rb" "$n" "$db"
  if (( ra == n && rb == n && da == n && db == n )); then break; fi
  sleep 5
done
echo
say alice /status; say bob /status; sleep 2
echo "== alice"; docker exec avl-alice cat /out
echo "== bob"; docker exec avl-bob cat /out
echo "== router netem log"; docker exec avl-router cat /netem.log
echo "== result"
echo "profile $profile via tc netem: alice received $ra/$n (acked $da), bob received $rb/$n (acked $db), $((SECONDS - start)) s"
(( ra == n && rb == n && da == n && db == n ))
