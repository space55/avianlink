#!/usr/bin/env bash
# Installs (or upgrades) the avianlink relay as a systemd service.
#
#   deploy/install-relay.sh [options]
#
#   --binary PATH             install this avianlink-relay instead of building one
#   --push-service HOST:PORT  wake phones through avianlink-push (new installs)
#   --retention-days N        how long packets are kept, 1-30 (new installs)
#   --uninstall               stop and remove the service and binary; keep the state
#   --dry-run                 print what would be done, change nothing
#
# Run it as yourself on the server; it uses sudo for the system parts. The
# binary is built from this checkout, or from GitHub when the script is run
# on its own (curl … | bash). Settings live in /etc/default/avianlink-relay,
# which an upgrade never overwrites. State lives in /var/lib/avianlink-relay.
set -euo pipefail

REPO="https://github.com/space55/avianlink"
BIN=/usr/local/bin/avianlink-relay
UNIT=/etc/systemd/system/avianlink-relay.service
ENVFILE=/etc/default/avianlink-relay
PORT=41000

binary=""
push=""
retention=""
uninstall=no
dry=no

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
die() { printf 'install-relay: %s\n' "$*" >&2; exit 1; }
say() { printf '==> %s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --binary) binary="${2:?--binary needs a path}"; shift 2 ;;
        --push-service) push="${2:?--push-service needs HOST:PORT}"; shift 2 ;;
        --retention-days) retention="${2:?--retention-days needs a number}"; shift 2 ;;
        --uninstall) uninstall=yes; shift ;;
        --dry-run) dry=yes; shift ;;
        -h | --help) usage 0 ;;
        *) printf 'unknown option: %s\n\n' "$1" >&2; usage 2 ;;
    esac
done

if [ -n "$retention" ]; then
    case "$retention" in
        '' | *[!0-9]*) die "--retention-days must be a number" ;;
    esac
    [ "$retention" -ge 1 ] && [ "$retention" -le 30 ] || die "--retention-days is 1 to 30"
fi
if [ -n "$push" ]; then
    case "$push" in
        *:*) ;;
        *) die "--push-service is HOST:PORT, for example push.avianlink.dev:41001" ;;
    esac
fi

# Privileged steps go through `as_root`; --dry-run prints them instead.
if [ "$(id -u)" -eq 0 ]; then SUDO=(); else SUDO=(sudo); fi
as_root() {
    if [ "$dry" = yes ]; then
        printf '    %s\n' "${SUDO[*]:+${SUDO[*]} }$*"
    else
        "${SUDO[@]}" "$@"
    fi
}

if [ "$dry" = no ]; then
    [ "$(uname -s)" = Linux ] || die "this installs a systemd service; run it on the Linux server"
    command -v systemctl >/dev/null || die "systemctl not found: this needs systemd"
    [ "${#SUDO[@]}" -eq 0 ] || command -v sudo >/dev/null || die "run as root, or install sudo"
fi

if [ "$uninstall" = yes ]; then
    say "removing the service and binary (state in /var/lib/avianlink-relay is kept)"
    as_root systemctl disable --now avianlink-relay.service
    as_root rm -f "$UNIT" "$BIN"
    as_root systemctl daemon-reload
    say "settings left in $ENVFILE; delete it and /var/lib/avianlink-relay to remove everything"
    exit 0
fi

# Where the unit and settings templates are: beside this script, or fetched.
here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
if [ -n "$here" ] && [ -f "$here/systemd/avianlink-relay.service" ]; then
    templates="$here/systemd"
    checkout="$(cd "$here/.." && pwd)"
else
    say "fetching the unit from $REPO"
    command -v git >/dev/null || die "git is needed to fetch the relay's files"
    git clone --quiet --depth 1 "$REPO" "$work/avianlink"
    templates="$work/avianlink/deploy/systemd"
    checkout="$work/avianlink"
fi

# The binary.
if [ -n "$binary" ]; then
    [ -x "$binary" ] || [ "$dry" = yes ] || die "$binary is not an executable"
    built="$binary"
else
    command -v cargo >/dev/null ||
        die "cargo not found; install Rust (https://rustup.rs) or pass --binary"
    say "building avianlink-relay from $checkout (a few minutes the first time)"
    if [ "$dry" = yes ]; then
        printf '    cargo install --locked --path %s --root %s\n' \
            "$checkout/crates/avianlink-udp" "$work/root"
    else
        cargo install --quiet --locked --path "$checkout/crates/avianlink-udp" \
            --root "$work/root" --bin avianlink-relay
    fi
    built="$work/root/bin/avianlink-relay"
fi

upgrade=no
[ -f "$UNIT" ] && upgrade=yes

say "installing $BIN and the service"
as_root install -m 0755 "$built" "$BIN"
as_root install -m 0644 "$templates/avianlink-relay.service" "$UNIT"

if [ -f "$ENVFILE" ]; then
    say "keeping your settings in $ENVFILE"
    if [ -n "$push$retention" ]; then
        say "  (--push-service and --retention-days apply to new installs; edit $ENVFILE instead)"
    fi
else
    args="--retention-days ${retention:-7}"
    [ -z "$push" ] || args="$args --push-service $push"
    say "writing $ENVFILE: $args"
    sed "s|^AVIANLINK_RELAY_ARGS=.*|AVIANLINK_RELAY_ARGS=\"$args\"|" \
        "$templates/avianlink-relay.env" >"$work/env"
    as_root install -m 0644 "$work/env" "$ENVFILE"
fi

as_root systemctl daemon-reload
if [ "$upgrade" = yes ]; then
    say "restarting the relay on the new binary"
    as_root systemctl restart avianlink-relay.service
else
    say "starting the relay"
    as_root systemctl enable --now avianlink-relay.service
fi

if [ "$dry" = yes ]; then
    say "dry run: nothing was changed"
    exit 0
fi

sleep 1
if systemctl is-active --quiet avianlink-relay.service; then
    say "running: $(journalctl -u avianlink-relay.service -n 1 --no-pager -o cat 2>/dev/null || true)"
else
    journalctl -u avianlink-relay.service -n 20 --no-pager >&2 || true
    die "the relay did not start; the log is above"
fi

cat <<EOF

The relay listens on UDP $PORT. Make sure that port is open:
  ufw:       sudo ufw allow $PORT/udp
  firewalld: sudo firewall-cmd --permanent --add-port=$PORT/udp && sudo firewall-cmd --reload
and that its DNS name is not proxied (proxies such as Cloudflare's drop UDP).

Settings: $ENVFILE, then sudo systemctl restart avianlink-relay
Logs:     journalctl -u avianlink-relay -f
EOF
