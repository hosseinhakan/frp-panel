#!/usr/bin/env bash
# install.sh — one-line curl installer for the FRP Tunnel Suite web panel.
#
# Typical use (root on a fresh Ubuntu/Debian VPS):
#
#   curl -fsSL https://raw.githubusercontent.com/hosseinhakan/frp-panel/main/scripts/install.sh | bash
#
# Flags:
#   --port N        panel listen port            (default: panel.toml 9000)
#   --bind ADDR     panel listen address         (default: 0.0.0.0, all interfaces;
#                   pass 127.0.0.1 for loopback-only or a GRE tunnel IP like
#                   10.100.111.2 for private-network access)
#   --version V     release tag to install       (default: latest)
#   --base URL      tarball base URL override    (FRP_PANEL_RELEASE_BASE works too)
#   --file PATH     install frp-panel from a local .tar.gz instead of downloading
#   --force-frp     reinstall the frps/frpc binaries even if they already exist
#   --help          this text
#
# What it does: ensure the frps/frpc binaries, /root/frp/{server,client} and the
# canonical frps@.service / frpc@.service units are in place (idempotent; only
# installed when missing or with --force-frp) → download (or use --file) the
# arch-matched release tarball and verify its SHA256 sidecar when published →
# install the binary (with the whole web UI embedded) → `frp-panel install-unit`
# writes the canonical systemd unit from inside the binary → enable + start →
# wait for panel.toml and verify the unit stayed active → print the access URLs
# and the one-time password hint.
set -euo pipefail

REPO="${FRP_PANEL_RELEASE_REPO:-https://github.com/hosseinhakan/frp-panel}"
BASE="${FRP_PANEL_RELEASE_BASE:-}"
VERSION="latest"
PORT=""
BIND=""
FILE=""
FORCE_FRP=0
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/frp-panel"
LOG_DIR="/var/log/frp-panel"
FRP_ROOT="/root/frp"
FRP_API="https://api.github.com/repos/fatedier/frp/releases/latest"

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
  --bind ADDR     panel listen address (default 0.0.0.0, all interfaces; pass
                  127.0.0.1 for loopback-only, or a GRE tunnel IP like
                  10.100.111.2 for private-network access)
  --version V     release tag         (default: latest)
  --base URL      tarball base URL override (FRP_PANEL_RELEASE_BASE works too)
  --file PATH     install frp-panel from a local .tar.gz (no download)
  --force-frp     reinstall frps/frpc even if already in /usr/local/bin
  --help          this text
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)   PORT="${2:?--port needs a value}"; shift 2 ;;
        --bind)   BIND="${2:?--bind needs a value}"; shift 2 ;;
        --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
        --base)   BASE="${2:?--base needs a value}"; shift 2 ;;
        --file)   FILE="${2:?--file needs a value}"; shift 2 ;;
        --force-frp) FORCE_FRP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown flag $1 (try --help)" ;;
    esac
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || die "must run as root (sudo)"
[[ "$(uname -s)" == "Linux" ]] || die "Linux only (this host: $(uname -s))"
for cmd in curl tar systemctl install cmp; do
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
if [[ -n "$FILE" ]]; then
    [[ -f "$FILE" ]] || die "--file: no such file: $FILE"
    [[ -r "$FILE" ]] || die "--file: not readable: $FILE"
    [[ "$FILE" == *.tar.gz ]] || die "--file: expected a .tar.gz archive"
    [[ "$VERSION" == "latest" && -z "$BASE" ]] || die "--file cannot be combined with --version or --base"
fi

# --- FRP core binaries + canonical units (idempotent) ------------------------
# The unit bodies below are byte-identical to the canonical assets in
# panel/internal/assets/systemd/ (also embedded in frp-setup.sh and the binary).
sync_unit() { # dest on argv, body on stdin; returns 0 only when the file changed
    local dest="$1" tmp
    tmp="$(mktemp)"
    cat > "$tmp"
    if [[ -f "$dest" ]] && cmp -s "$tmp" "$dest"; then
        rm -f "$tmp"
        return 1
    fi
    install -m 0644 "$tmp" "$dest"
    rm -f "$tmp"
    return 0
}

ensure_frp_units() {
    local changed=0
    if sync_unit /etc/systemd/system/frps@.service <<'ASSET_FRPS_SERVICE'
[Unit]
Description=FRP Server Service (%i)
Documentation=https://gofrp.org/en/docs/overview/
StartLimitIntervalSec=0
StartLimitBurst=0
After=network.target nss-lookup.target network-online.target
Wants=network-online.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_BIND_SERVICE CAP_SYS_PTRACE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=/usr/local/bin/frps -c /root/frp/server/%i.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=2s
Nice=-10
OOMScoreAdjust=-900
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
ASSET_FRPS_SERVICE
    then
        changed=1
    fi
    if sync_unit /etc/systemd/system/frpc@.service <<'ASSET_FRPC_SERVICE'
[Unit]
Description=FRP Client Service (%i)
Documentation=https://gofrp.org/en/docs/overview/
StartLimitIntervalSec=0
StartLimitBurst=0
After=network.target nss-lookup.target network-online.target
Wants=network-online.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE CAP_NET_BIND_SERVICE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE CAP_SYS_BIND_SERVICE CAP_SYS_PTRACE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=/usr/local/bin/frpc -c /root/frp/client/%i.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=2s
Nice=-10
OOMScoreAdjust=-900
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
ASSET_FRPC_SERVICE
    then
        changed=1
    fi
    if (( changed )); then
        systemctl daemon-reload
    fi
}

install_frp_core() {
    say "ensuring FRP core (frps + frpc) and systemd units"
    mkdir -p "${FRP_ROOT}/server" "${FRP_ROOT}/client"
    ensure_frp_units
    systemctl daemon-reload

    if (( FORCE_FRP )) || [[ ! -x "${BIN_DIR}/frps" || ! -x "${BIN_DIR}/frpc" ]]; then
        say "fetching the latest FRP release tag from GitHub"
        local tag ver tar_name frp_url tmp src
        tag="$(curl -fsSL --retry 3 "$FRP_API" 2>/dev/null \
            | sed -nE 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' \
            | head -n1 || true)"
        [[ -n "$tag" ]] || die "could not read the latest FRP tag from $FRP_API (rate-limited? retry later)"
        ver="${tag#v}"
        tar_name="frp_${ver}_linux_${arch}.tar.gz"
        frp_url="https://github.com/fatedier/frp/releases/download/${tag}/${tar_name}"

        tmp="$(mktemp -d)"
        say "downloading FRP ${ver} (${frp_url})"
        if ! curl -fL --retry 3 "$frp_url" -o "$tmp/frp.tar.gz"; then
            rm -rf "$tmp"
            die "FRP download failed: $frp_url"
        fi
        if ! tar -xzf "$tmp/frp.tar.gz" -C "$tmp"; then
            rm -rf "$tmp"
            die "could not extract ${tar_name}"
        fi
        src="$tmp/frp_${ver}_linux_${arch}"
        if [[ ! -f "$src/frps" || ! -f "$src/frpc" ]]; then
            rm -rf "$tmp"
            die "archive ${tar_name} did not contain frps and frpc"
        fi
        install -m 0755 "$src/frps" "${BIN_DIR}/frps"
        install -m 0755 "$src/frpc" "${BIN_DIR}/frpc"
        rm -rf "$tmp"
    else
        say "FRP binaries already present in ${BIN_DIR} (use --force-frp to reinstall)"
    fi

    local frp_ver
    frp_ver="$("${BIN_DIR}/frps" --version 2>/dev/null | head -n1 || true)"
    ok "FRP ready: ${frp_ver:-frps --version unavailable} (${BIN_DIR}/frps, ${BIN_DIR}/frpc)"
    say "config dirs: ${FRP_ROOT}/server ${FRP_ROOT}/client; units: frps@.service frpc@.service"
}

install_frp_core

# --- download (or reuse) the panel release tarball ---------------------------
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

verify_sha256() { # verify_sha256 <archive> <sidecar>
    local archive="$1" sidecar="$2" expected actual
    if ! command -v sha256sum >/dev/null 2>&1; then
        say "sha256sum unavailable — skipping checksum verification"
        return 0
    fi
    expected="$(awk 'NR == 1 { print $1 }' "$sidecar" 2>/dev/null || true)"
    [[ -n "$expected" ]] || { say "checksum file is empty — skipping verification"; return 0; }
    actual="$(sha256sum "$archive" | awk '{ print $1 }')"
    [[ "$expected" == "$actual" ]] \
        || die "SHA256 mismatch for ${archive} (expected ${expected}, got ${actual})"
    ok "SHA256 verified (${actual})"
}

asset="frp-panel_linux_${arch}.tar.gz"
if [[ -n "$FILE" ]]; then
    say "using local tarball ${FILE}"
    cp "$FILE" "$stage/panel.tar.gz"
    if [[ -f "${FILE}.sha256" ]]; then
        verify_sha256 "$stage/panel.tar.gz" "${FILE}.sha256"
    fi
else
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

    say "downloading ${url}"
    curl -fL --retry 3 "$url" -o "$stage/panel.tar.gz" \
        || die "download failed — release not published yet, or unreachable. Set FRP_PANEL_RELEASE_BASE or --base to a mirror."
    if curl -fsSL --retry 1 --max-time 10 "${url}.sha256" -o "$stage/panel.tar.gz.sha256" 2>/dev/null; then
        verify_sha256 "$stage/panel.tar.gz" "$stage/panel.tar.gz.sha256"
    else
        say "no SHA256 sidecar at ${url}.sha256 — skipping verification"
    fi
fi

tar -xzf "$stage/panel.tar.gz" -C "$stage"
[[ -f "$stage/frp-panel" ]] || die "tarball does not contain ./frp-panel"

install -m 0755 "$stage/frp-panel" "${BIN_DIR}/frp-panel"
mkdir -p "$CONF_DIR" "$LOG_DIR"

# --- install + start the panel ------------------------------------------------
# The unit ships from inside the binary (same canonical asset the CLI
# installs and check-sync.sh guards) — one source of truth.
"${BIN_DIR}/frp-panel" install-unit
systemctl daemon-reload
systemctl enable --now frp-panel

wait_for_panel_conf() { # first start bootstraps panel.toml; poll up to 10s
    local i
    for (( i = 0; i < 20; i++ )); do
        [[ -s "${CONF_DIR}/panel.toml" ]] && return 0
        sleep 0.5
    done
    return 1
}

assert_panel_active() {
    local i
    for (( i = 0; i < 20; i++ )); do
        systemctl is-active --quiet frp-panel && return 0
        sleep 0.5
    done
    echo -e "${c_bad}frp-panel:${c_off} frp-panel.service is not active — last 20 journal lines:" >&2
    journalctl -u frp-panel --no-pager -n 20 1>&2 2>/dev/null || true
    exit 1
}

read_panel_conf() { # read_panel_conf <key> <default>
    local key="$1" def="$2" val=""
    if [[ -r "${CONF_DIR}/panel.toml" ]]; then
        val="$(sed -nE "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*['\"]?([^'\"]*)['\"]?[[:space:]]*$/\1/p" \
            "${CONF_DIR}/panel.toml" | head -n1)"
    fi
    echo "${val:-$def}"
}

panel_bind_is_loopback() {
    case "$1" in
        127.0.0.1|localhost|::1|"[::1]") return 0 ;;
        *) return 1 ;;
    esac
}

open_panel_firewall() { # open_panel_firewall <bind> <port>
    local bind="$1" port="$2"
    panel_bind_is_loopback "$bind" && return 0
    if command -v ufw >/dev/null 2>&1; then
        if ufw allow "${port}/tcp" >/dev/null 2>&1; then
            say "opened UFW port ${port}/tcp for the panel (bind ${bind})"
        else
            say "note: ufw is installed but 'ufw allow ${port}/tcp' failed — open it manually if the panel is unreachable"
        fi
    fi
}

if ! wait_for_panel_conf; then
    echo -e "${c_bad}frp-panel:${c_off} ${CONF_DIR}/panel.toml was not created within 10s — last 20 journal lines:" >&2
    journalctl -u frp-panel --no-pager -n 20 1>&2 2>/dev/null || true
    exit 1
fi
assert_panel_active

# Optional listen overrides: adjust the bootstrapped panel.toml and restart.
# (go-toml renders single-quoted strings; the sed matches both quote styles.)
if [[ -n "$PORT" || -n "$BIND" ]]; then
    if [[ -r "${CONF_DIR}/panel.toml" ]]; then
        [[ -n "$BIND" ]] && sed -i -E "s/^[[:space:]]*bind[[:space:]]*=.*/bind = '${BIND}'/" "${CONF_DIR}/panel.toml"
        [[ -n "$PORT" ]] && sed -i -E "s/^[[:space:]]*port[[:space:]]*=.*/port = ${PORT}/" "${CONF_DIR}/panel.toml"
        systemctl restart frp-panel
        assert_panel_active
        ok "panel reconfigured (bind=${BIND:-unchanged} port=${PORT:-unchanged})"
    else
        die "panel.toml missing after first start — check: journalctl -u frp-panel -n 20"
    fi
fi

# Open the panel port when it is reachable beyond loopback. Runs after the
# optional listen overrides so a loopback-only rerun never leaves a public rule.
open_panel_firewall "$(read_panel_conf bind "0.0.0.0")" "$(read_panel_conf port "9000")"

# --- access URLs --------------------------------------------------------------
# Read what the panel actually listens on (flags are only fallbacks).
public_ipv4_addrs() { # deduplicated, non-loopback, non-container IPv4 addresses
    ip -o -4 addr show 2>/dev/null \
        | awk '$2 != "lo" && $2 !~ /^(docker|br-|veth|virbr|podman|cni|flannel)/ {
              split($4, a, "/")
              if (a[1] !~ /^127\./ && !seen[a[1]]++) print a[1]
          }'
}

detect_public_ip() {
    local candidate
    candidate="$(ip -o -4 route get 1.1.1.1 2>/dev/null \
        | awk '{ for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit } }' || true)"
    case "$candidate" in
        10.*|127.*|169.254.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|"") ;;
        *) echo "$candidate"; return 0 ;;
    esac
    candidate="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    echo "${candidate:-<public-ip>}"
}

bind="$(read_panel_conf bind "0.0.0.0")"
port="$(read_panel_conf port "9000")"
[[ -n "$BIND" ]] && bind="$BIND"
[[ -n "$PORT" ]] && port="$PORT"

echo
ok "FRP Tunnel Suite panel installed and running."
echo
say "one-time admin password (first start only):"
echo "    journalctl -u frp-panel --no-pager | grep -i password | head -n1"
echo
say "access URLs:"
case "$bind" in
    ::1|"[::1]")
        echo "    http://[::1]:${port}"
        echo
        say "the panel listens on IPv6 loopback only — tunnel it from your workstation:"
        echo "    ssh -L ${port}:127.0.0.1:${port} root@$(detect_public_ip)"
        echo
        echo "    (or expose it directly: rerun with --bind 0.0.0.0)"
        ;;
    127.0.0.1|localhost)
        echo "    http://127.0.0.1:${port}"
        echo
        say "the panel listens on loopback only — tunnel it from your workstation:"
        echo "    ssh -L ${port}:127.0.0.1:${port} root@$(detect_public_ip)"
        echo
        echo "    (or expose it directly: rerun with --bind 0.0.0.0)"
        ;;
    0.0.0.0|::)
        found=0
        while IFS= read -r addr; do
            [[ -n "$addr" ]] || continue
            echo "    http://${addr}:${port}"
            found=$((found + 1))
        done < <(public_ipv4_addrs)
        if (( found == 0 )); then
            echo "    (no non-loopback IPv4 address found — use --bind 127.0.0.1 and an ssh tunnel)"
        fi
        ;;
    *)
        echo "    http://${bind}:${port}"
        ;;
esac
echo
say "sign in, change the one-time password, then create your first GRE tunnel or FRP instance."
