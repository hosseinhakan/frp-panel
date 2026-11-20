#!/usr/bin/env bash
# install.sh — one-line curl installer for the FRP Tunnel Suite web panel.
#
# Typical use (root on a fresh Ubuntu/Debian VPS):
#
#   curl -fsSL https://raw.githubusercontent.com/hosseinhakan/frp-panel/main/scripts/install.sh | bash
#
# Flags:
#   --port N        panel listen port            (default: panel.toml 9000)
#   --bind ADDR     panel listen address         (default: 127.0.0.1; use a GRE
#                   tunnel IP like 10.100.111.2 for private-network access)
#   --version V     release tag to install       (default: latest)
#   --base URL      tarball base URL override    (FRP_PANEL_RELEASE_BASE works too)
#   --help          this text
#
# What it does: download the arch-matched release tarball → install the
# binary (with the whole web UI embedded) → `frp-panel install-unit` writes
# the canonical systemd unit from inside the binary → enable + start →
# print the access URLs and the one-time password hint.
set -euo pipefail

REPO="${FRP_PANEL_RELEASE_REPO:-https://github.com/hosseinhakan/frp-panel}"
BASE="${FRP_PANEL_RELEASE_BASE:-}"
VERSION="latest"
PORT=""
BIND=""
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/frp-panel"
LOG_DIR="/var/log/frp-panel"

c_ok=$'\033[0;32m'; c_bad=$'\033[0;31m'; c_info=$'\033[0;36m'; c_off=$'\033[0m'
say()   { echo -e "${c_info}frp-panel:${c_off} $*"; }
ok()    { echo -e "${c_ok}frp-panel:${c_off} $*"; }
die()   { echo -e "${c_bad}frp-panel:${c_off} $*" >&2; exit 1; }

usage() {
    cat <<'EOF'
install.sh — one-line curl installer for the FRP Tunnel Suite web panel.

Typical use (root on a fresh Ubuntu/Debian VPS):

  curl -fsSL https://raw.githubusercontent.com/hosseinhakan/frp-panel/main/scripts/install.sh | bash

Flags:
  --port N        panel listen port    (default: panel.toml 9000)
  --bind ADDR     panel listen address (default 127.0.0.1; use a GRE tunnel
                  IP like 10.100.111.2 for private-network access)
  --version V     release tag         (default: latest)
  --base URL      tarball base URL override (FRP_PANEL_RELEASE_BASE works too)
  --help          this text
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)   PORT="${2:?--port needs a value}"; shift 2 ;;
        --bind)   BIND="${2:?--bind needs a value}"; shift 2 ;;
        --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
        --base)   BASE="${2:?--base needs a value}"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown flag $1 (try --help)" ;;
    esac
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || die "must run as root (sudo)"
[[ "$(uname -s)" == "Linux" ]] || die "Linux only (this host: $(uname -s))"
for cmd in curl tar systemctl install; do
    command -v "$cmd" >/dev/null 2>&1 || die "missing required command: $cmd"
done
case "$(uname -m)" in
    x86_64)         arch="amd64" ;;
    aarch64|arm64)  arch="arm64" ;;
    *) die "unsupported architecture: $(uname -m)" ;;
esac
if [[ -n "$PORT" ]]; then
    [[ "$PORT" =~ ^[0-9]+$ ]] || die "--port must be numeric"
    (( PORT >= 1 && PORT <= 65535 )) || die "--port must be 1..65535"
fi
if [[ -n "$BIND" ]]; then
    [[ "$BIND" =~ ^[A-Za-z0-9.:-]+$ ]] || die "--bind must be a single IP address (no spaces or commas)"
fi

asset="frp-panel_linux_${arch}.tar.gz"
if [[ -n "$BASE" ]]; then
    [[ "$VERSION" == "latest" ]] || die "--version requires the default download base; drop --base"
    url="${BASE%/}/${asset}"
else
    if [[ "$VERSION" == "latest" ]]; then
        url="${REPO}/releases/latest/download/${asset}"
    else
        v="${VERSION#v}"
        url="${REPO}/releases/download/v${v}/${asset}"
    fi
fi

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

say "downloading ${url}"
curl -fL --retry 3 "$url" -o "$stage/panel.tar.gz" || die "download failed — release not published yet, or unreachable. Set FRP_PANEL_RELEASE_BASE or --base to a mirror."
tar -xzf "$stage/panel.tar.gz" -C "$stage"
[[ -f "$stage/frp-panel" ]] || die "tarball does not contain ./frp-panel"

install -m 0755 "$stage/frp-panel" "${BIN_DIR}/frp-panel"
mkdir -p "$CONF_DIR" "$LOG_DIR"

# The unit ships from inside the binary (same canonical asset the CLI
# installs and check-sync.sh guards) — one source of truth.
"${BIN_DIR}/frp-panel" install-unit
systemctl daemon-reload
systemctl enable --now frp-panel
sleep 1

# Optional listen overrides: adjust the bootstrapped panel.toml and restart.
# (go-toml renders single-quoted strings; the sed matches both quote styles.)
if [[ -n "$PORT" || -n "$BIND" ]]; then
    if [[ -r "${CONF_DIR}/panel.toml" ]]; then
        [[ -n "$BIND" ]] && sed -i -E "s/^bind *=.*/bind = '${BIND}'/" "${CONF_DIR}/panel.toml"
        [[ -n "$PORT" ]] && sed -i -E "s/^port *=.*/port = ${PORT}/" "${CONF_DIR}/panel.toml"
        systemctl restart frp-panel
        sleep 1
        ok "panel reconfigured (bind=${BIND:-unchanged} port=${PORT:-unchanged})"
    else
        die "panel.toml missing after first start — check: journalctl -u frp-panel -n 20"
    fi
fi

echo
ok "FRP Tunnel Suite panel installed and running."
echo
say "one-time admin password (first start only):"
echo "    journalctl -u frp-panel --no-pager | grep -i password | head -n1"
echo
say "access URLs:"
conf_port="$(sed -nE 's/^port *= *([0-9]+).*/\1/p' "${CONF_DIR}/panel.toml" 2>/dev/null | head -n1)"
port="${PORT:-${conf_port:-9000}}"
echo "    http://127.0.0.1:${port}"
for ip in $(ip -o -4 addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1); do
    echo "    http://${ip}:${port}"
done
echo
say "sign in, change the one-time password, then create your first GRE tunnel or FRP instance."
