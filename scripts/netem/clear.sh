#!/bin/sh
# Removes netem qdiscs. Usage (as root): clear.sh DEV [DEV...]
set -eu
for dev in "$@"; do tc qdisc del dev "$dev" root 2>/dev/null || true; done
