#!/bin/bash
# ==============================================================================
# FRP Tunnel Suite — CLI (frp-manager)
#
# v2 upgrade of the original FRP Management Tool. Menu items 1-9 keep their
# exact positions, labels and flows (full CLI compatibility); new suite
# features are appended as items 10-13.
#
# New in v2:
#   - auth.token: generated 32-char random token by default (no static default)
#   - bindAddr choice incl. private GRE/tunnel IPs (e.g. 10.100.111.2)
#   - client defaults: tls.enable=true, useEncryption=true, compression=false
#   - dual TCP+UDP forwarding with a single toggle (tcp-<p> + udp-<p> blocks)
#   - 10) GRE Tunnel Manager (gt11-style, conntrack bypass, MSS clamping)
#   - 11) Web Panel manager (installs frp-panel as systemd service)
#   - 12) Backup / Restore (tar.gz of /root/frp + units + turbo + panel)
#   - 13) Watchdog & Health (auto-heal GRE + frpc, live health check)
#   - Optimization Utilities -> persistent tunnel-turbo.service + optional ZRAM
#   - non-interactive subcommands: frp-manager gre|panel|turbo|backup|watchdog
#
# Canonical systemd units and helpers live in panel/internal/assets/ and are
# embedded below as heredocs; scripts/check-sync.sh verifies they match.
# ==============================================================================
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- constants ---------------------------------------------------------------
VERSION="2.0.0"
INSTALL_PATH="/usr/local/bin/frp-manager"
SCRIPT_PATH="$(readlink -f "$0")"

FRP_ROOT="/root/frp"
SERVER_DIR="$FRP_ROOT/server"
CLIENT_DIR="$FRP_ROOT/client"
GRE_DIR="$FRP_ROOT/gre"
PANEL_CONF_DIR="/etc/frp-panel"
PANEL_LOG_DIR="/var/log/frp-panel"
PANEL_DEFAULT_PORT=9000
# Optional: install the CLI itself from a remote URL instead of copying
# this file (the old default pulled a stale upstream copy — now local-copy).
FRP_SETUP_SOURCE_URL="${FRP_SETUP_SOURCE_URL:-}"
# Release location serving frp-panel_linux_<arch>.tar.gz (set by CI).
PANEL_RELEASE_BASE="${FRP_PANEL_RELEASE_BASE:-https://github.com/hosseinhakan/frp-panel/releases/latest/download}"

# --- print helpers (unchanged from v1) ---------------------------------------
print_header() {
    echo -e "${BLUE}=================================${NC}"
    echo -e "${BLUE}       FRP Management Tool       ${NC}"
    echo -e "${BLUE}=================================${NC}"
    echo -e "${BLUE}      Tunnel Suite v${VERSION}      ${NC}"
    echo
}

print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

print_info() {
    echo -e "${BLUE}[+] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

print_error() {
    echo -e "${RED}[✗] $1${NC}"
}

pause() {
    read -p "Press Enter to continue..."
}

confirm_yes() { # confirm_yes "Question?" — returns 0 only on explicit yes
    read -p "$1 (yes/no): " answer
    [[ "$answer" == "yes" ]]
}

# --- small helpers -----------------------------------------------------------
gen_token() { # 32-char strong alphanumeric token (replaces static defaults)
    head -c 256 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 32
}

is_valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && (( 1 <= $1 && $1 <= 65535 ))
}

is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

is_cidr4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]
}

port_in_use() { # TCP listen check via ss
    ss -ltnH "( sport = :$1 )" 2>/dev/null | grep -q .
}

# allocate_web_port LO HI DIR — echoes the first free metrics/dash port,
# avoiding live sockets and any port already referenced in DIR's configs.
allocate_web_port() {
    local lo="$1" hi="$2" dir="$3" p
    for p in $(seq "$lo" "$hi"); do
        if port_in_use "$p"; then continue; fi
        if grep -RqsE "(webServer\.port|bindPort|quicBindPort|kcpBindPort|remotePort) = $p$" "$dir" 2>/dev/null; then
            continue
        fi
        echo "$p"
        return 0
    done
    return 1
}

detect_public_ip() { # best-effort default for prompts
    ip -o -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true
}

# sync_asset DEST MODE — asset body on stdin; returns 0 if the file changed.
sync_asset() {
    local dest="$1" mode="${2:-0644}" tmp
    tmp=$(mktemp)
    cat > "$tmp"
    if [[ -f "$dest" ]] && cmp -s "$tmp" "$dest"; then
        rm -f "$tmp"
        return 1
    fi
    mkdir -p "$(dirname "$dest")"
    cat "$tmp" > "$dest"
    chmod "$mode" "$dest"
    rm -f "$tmp"
    return 0
}

# --- asset installers (heredocs == panel/internal/assets/, see check-sync) ---

ensure_gre_assets() {
    local changed=""
    if sync_asset /usr/local/bin/frp-gre 0755 <<'ASSET_FRP_GRE'
#!/bin/bash
# frp-gre — GRE tunnel lifecycle helper (FRP Tunnel Suite).
# Canonical copy: panel/internal/assets/helpers/frp-gre (also embedded in frp-panel).
# Managed by frp-manager (CLI) and frp-panel (Web UI) — both write the same
# /root/frp/gre/*.env definitions and drive this script via gre-tunnel@.service.
#
# The unit runs `up` once (ExecStartPre) and then `hold`, which keeps
# re-asserting the interface + rules and lets systemd's Restart=always rebuild
# the tunnel after a fatal failure. Every iptables change is -C-checked, so
# repeated calls never duplicate rules.
#
# Usage: frp-gre up|down|reload|hold|status <tunnel-name>
set -euo pipefail

ENV_DIR="${FRP_GRE_ENV_DIR:-/root/frp/gre}"
HOLD_INTERVAL="${FRP_GRE_HOLD_INTERVAL:-10}"
IPT_WAIT="${FRP_GRE_IPT_WAIT:-5}"
TUNING_DROPIN="/etc/sysctl.d/99-tunnel-turbo.conf"

usage() { echo "usage: frp-gre up|down|reload|hold|status <tunnel-name>" >&2; exit 2; }

load_env() {
    local name="${1:-}"
    [[ "$name" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || { echo "frp-gre: invalid tunnel name '$name'" >&2; exit 2; }
    local env_file="$ENV_DIR/$name.env"
    [[ -r "$env_file" ]] || { echo "frp-gre: missing env file $env_file" >&2; exit 1; }

    LOCAL_PUBLIC_IP=""; REMOTE_PUBLIC_IP=""; IFACE=""; LOCAL_PRIVATE_IP=""; REMOTE_PRIVATE_IP=""
    MTU=""; MSS_MODE="clamp"; TXQUEUELEN=""
    # shellcheck disable=SC1090
    source "$env_file"

    [[ -n "$LOCAL_PUBLIC_IP" && -n "$REMOTE_PUBLIC_IP" && -n "$IFACE" \
       && -n "$LOCAL_PRIVATE_IP" && -n "$REMOTE_PRIVATE_IP" ]] \
        || { echo "frp-gre: $env_file is missing required fields" >&2; exit 1; }
    MTU="${MTU:-1320}"
    MSS_MODE="${MSS_MODE:-clamp}"
    TXQUEUELEN="${TXQUEUELEN:-1000}"
    [[ "$TXQUEUELEN" =~ ^[0-9]+$ ]] || TXQUEUELEN=1000
}

ipt() { iptables -w "$IPT_WAIT" "$@"; }

ipt_ensure() { # ipt_ensure <table> <chain> <rule...> — add once, idempotent
    local table="$1" chain="$2"; shift 2
    ipt -t "$table" -C "$chain" "$@" >/dev/null 2>&1 \
        || ipt -t "$table" -A "$chain" "$@"
}

ipt_purge() { # ipt_purge <table> <chain> <rule...> — remove every instance
    local table="$1" chain="$2"; shift 2
    while ipt -t "$table" -C "$chain" "$@" >/dev/null 2>&1; do
        ipt -t "$table" -D "$chain" "$@" >/dev/null 2>&1 || break
    done
}

notrack_ensure() { # notrack_ensure <PREROUTING|OUTPUT> — bypass conntrack for GRE (proto 47)
    local chain="$1"
    ipt -t raw -C "$chain" -p 47 -j CT --notrack >/dev/null 2>&1 && return 0
    ipt -t raw -C "$chain" -p 47 -j NOTRACK >/dev/null 2>&1 && return 0
    ipt -t raw -A "$chain" -p 47 -j CT --notrack >/dev/null 2>&1 \
        || ipt -t raw -A "$chain" -p 47 -j NOTRACK
}

notrack_purge() {
    ipt_purge raw "$1" -p 47 -j CT --notrack
    ipt_purge raw "$1" -p 47 -j NOTRACK
}

mss_rules() { # TCPMSS clamping on the GRE interface + host-local traffic
    case "$MSS_MODE" in
        clamp|1360|1240|1220) ;;
        off) return 0 ;;
        *) echo "frp-gre: unknown MSS_MODE '$MSS_MODE', defaulting to clamp" >&2; MSS_MODE=clamp ;;
    esac
    local args
    [[ "$MSS_MODE" == "clamp" ]] && args="--clamp-mss-to-pmtu" || args="--set-mss $MSS_MODE"
    # shellcheck disable=SC2086
    ipt_ensure mangle FORWARD -o "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS $args
    # shellcheck disable=SC2086
    ipt_ensure mangle FORWARD -i "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS $args
    # frps/frpc on THIS host originate their SYN via OUTPUT → POSTROUTING, which
    # bypasses FORWARD. Without this rule PMTUD blackholes stall the control
    # channel. Always pin a safe MSS (1220) rather than relying on PMTUD.
    local local_mss
    case "$MSS_MODE" in
        1360|1240|1220) local_mss="$MSS_MODE" ;;
        *) local_mss="1220" ;;
    esac
    ipt_ensure mangle POSTROUTING -o "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$local_mss"
}

mss_purge() { # remove every MSS variant for this interface
    local variant
    for variant in "--clamp-mss-to-pmtu" "--set-mss 1360" "--set-mss 1240" "--set-mss 1220"; do
        # shellcheck disable=SC2086
        ipt_purge mangle FORWARD -o "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS $variant
        # shellcheck disable=SC2086
        ipt_purge mangle FORWARD -i "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS $variant
        # shellcheck disable=SC2086
        ipt_purge mangle POSTROUTING -o "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS $variant
    done
}

forward_rules() { # allow transit when the FORWARD policy is DROP
    [[ "$(ipt -S FORWARD 2>/dev/null | head -n1)" == *"-P FORWARD DROP"* ]] || return 0
    ipt_ensure filter FORWARD -i "$IFACE" -j ACCEPT
    ipt_ensure filter FORWARD -o "$IFACE" -j ACCEPT
}

forward_purge() {
    ipt_purge filter FORWARD -i "$IFACE" -j ACCEPT
    ipt_purge filter FORWARD -o "$IFACE" -j ACCEPT
}

apply_tuning() { # zero-drop kernel tuning + per-interface rp_filter
    local tmp="$TUNING_DROPIN.tmp"
    mkdir -p /etc/sysctl.d
    cat > "$tmp" <<'FRP_TUNING'
# /etc/sysctl.d/99-tunnel-turbo.conf — FRP Tunnel Suite zero-drop tuning
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 1024
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6
net.ipv4.tcp_tw_reuse = 1
FRP_TUNING
    # Only persist the conntrack key when the table is loaded: an unknown key
    # would make every later `sysctl --system` fail on hosts without it.
    if [[ -e /proc/sys/net/netfilter/nf_conntrack_max ]]; then
        echo "net.netfilter.nf_conntrack_max = 524288" >> "$tmp"
    fi
    if [[ ! -f "$TUNING_DROPIN" ]] || ! cmp -s "$tmp" "$TUNING_DROPIN"; then
        mv -f "$tmp" "$TUNING_DROPIN"
        sysctl --system >/dev/null 2>&1 || true
    else
        rm -f "$tmp"
    fi
    # 16 KB tcp_notsent_lowat starves bulk video streams (YouTube 1080p/4K) on
    # 40–100 ms WAN links, and TCP Fast Open payloads stall on Iranian
    # ISP/DPI middleboxes. Both keys are gone from the drop-in; reset their
    # *runtime* values too, because removing a key never un-applies it.
    sysctl -w net.ipv4.tcp_notsent_lowat=4294967295 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_fastopen=0 >/dev/null 2>&1 || true
    # BBR is a module on most kernels: make it load now and at every boot so
    # the congestion-control key above never fails silently after a reboot.
    mkdir -p /etc/modules-load.d
    echo tcp_bbr > /etc/modules-load.d/bbr.conf
    modprobe tcp_bbr 2>/dev/null || true
    # Never let reverse GRE packets be dropped by rp_filter, even when the
    # drop-in could not be applied at boot time.
    local key want
    for key in "net.ipv4.conf.${IFACE}.rp_filter" net.ipv4.conf.all.rp_filter \
               net.ipv4.tcp_mtu_probing net.ipv4.tcp_base_mss; do
        want=0
        case "$key" in
            *.tcp_mtu_probing) want=1 ;;
            *.tcp_base_mss) want=1024 ;;
        esac
        if ! sysctl -w "${key}=${want}" >/dev/null 2>&1; then
            echo "frp-gre: warning: could not set ${key}=${want}" >&2
        fi
    done
}

conflicting_tunnels() {
    # A keyless GRE cannot have two interfaces with the same remote endpoint.
    # Print any *other* live interface already pointed at this remote so the
    # caller can fail loudly instead of deleting someone else's tunnel.
    ip -d tunnel show 2>/dev/null | awk -v r="$REMOTE_PUBLIC_IP" -v self="$IFACE" '
        $2 ~ /^gre(\/|$)/ {
            name = $1; sub(/:$/, "", name)
            if (name == self) next
            for (i = 3; i < NF; i++) if ($i == "remote" && $(i + 1) == r) { print name; break }
        }'
}

cmd_up() {
    load_env "${1:-}"
    if ip link show "$IFACE" >/dev/null 2>&1; then
        # Never repoint a live interface: a mismatched endpoint is a conflict
        # the operator must resolve explicitly.
        local live_remote live_local
        live_remote="$(ip -d tunnel show "$IFACE" 2>/dev/null | awk '$2 ~ /^gre(\/|$)/ {for (i = 3; i < NF; i++) if ($i == "remote") { print $(i + 1); exit }}')"
        live_local="$(ip -d tunnel show "$IFACE" 2>/dev/null | awk '$2 ~ /^gre(\/|$)/ {for (i = 3; i < NF; i++) if ($i == "local") { print $(i + 1); exit }}')"
        if [[ -n "$live_remote" && "$live_remote" != "$REMOTE_PUBLIC_IP" ]]; then
            echo "frp-gre: $IFACE already points at remote $live_remote, expected $REMOTE_PUBLIC_IP — refusing to modify it (stop/delete it explicitly first)" >&2
            exit 1
        fi
        if [[ -n "$live_local" && "$live_local" != "$LOCAL_PUBLIC_IP" ]]; then
            echo "frp-gre: $IFACE already uses local $live_local, expected $LOCAL_PUBLIC_IP — refusing to modify it (stop/delete it explicitly first)" >&2
            exit 1
        fi
        echo "frp-gre: interface $IFACE already exists, refreshing rules (never deleting it)"
    else
        local conflict
        conflict="$(conflicting_tunnels)"
        if [[ -n "$conflict" ]]; then
            echo "frp-gre: refusing to create $IFACE: GRE tunnel(s) $conflict already target remote $REMOTE_PUBLIC_IP — stop/delete them explicitly first" >&2
            exit 1
        fi
        ip tunnel add "$IFACE" mode gre local "$LOCAL_PUBLIC_IP" remote "$REMOTE_PUBLIC_IP" ttl 255
    fi
    # Re-assert only what actually differs: rewriting the address or MTU of a
    # healthy carrying tunnel can drop in-flight traffic.
    if ! ip -o -4 addr show dev "$IFACE" 2>/dev/null | grep -qw "${LOCAL_PRIVATE_IP%%/*}"; then
        ip addr replace "$LOCAL_PRIVATE_IP" dev "$IFACE" 2>/dev/null || true
    fi
    local cur_mtu cur_state
    cur_mtu="$(cat "/sys/class/net/$IFACE/mtu" 2>/dev/null || echo '')"
    [[ -n "$cur_mtu" && "$cur_mtu" == "$MTU" ]] || ip link set dev "$IFACE" mtu "$MTU"
    cur_state="$(cat "/sys/class/net/$IFACE/operstate" 2>/dev/null || echo '')"
    [[ "$cur_state" == "up" || "$cur_state" == "unknown" ]] || ip link set dev "$IFACE" up
    local cur_txq
    cur_txq="$(cat "/sys/class/net/$IFACE/tx_queue_len" 2>/dev/null || echo '')"
    [[ -n "$cur_txq" && "$cur_txq" == "$TXQUEUELEN" ]] || ip link set dev "$IFACE" txqueuelen "$TXQUEUELEN" 2>/dev/null || true
    apply_tuning
    notrack_ensure PREROUTING
    notrack_ensure OUTPUT
    mss_rules
    forward_rules
    echo "frp-gre: $IFACE up — local $LOCAL_PRIVATE_IP  peer $REMOTE_PRIVATE_IP  mtu $MTU  mss=$MSS_MODE  txq=$TXQUEUELEN"
}

cmd_hold() { # long-running keeper used by gre-tunnel@.service (Type=simple)
    load_env "${1:-}"
    trap 'exit 0' TERM INT
    while true; do
        if ! cmd_up "$1" >/dev/null 2>&1; then
            echo "frp-gre: $IFACE re-ensure failed; exiting so systemd can restart the unit" >&2
            exit 1
        fi
        sleep "$HOLD_INTERVAL"
    done
}

cmd_down() {
    load_env "${1:-}"
    notrack_purge PREROUTING
    notrack_purge OUTPUT
    mss_purge
    forward_purge
    ip link set "$IFACE" down >/dev/null 2>&1 || true
    ip tunnel del "$IFACE" >/dev/null 2>&1 || ip link del "$IFACE" >/dev/null 2>&1 || true
    echo "frp-gre: $IFACE down"
}

cmd_reload() { cmd_down "${1:-}"; cmd_up "${1:-}"; }

cmd_status() {
    load_env "${1:-}"
    if ! ip link show "$IFACE" >/dev/null 2>&1; then
        echo "frp-gre: $IFACE DOWN (interface missing)"
        exit 1
    fi
    local rx_b tx_b rx_p tx_p
    rx_b=$(cat "/sys/class/net/$IFACE/statistics/rx_bytes" 2>/dev/null || echo 0)
    tx_b=$(cat "/sys/class/net/$IFACE/statistics/tx_bytes" 2>/dev/null || echo 0)
    rx_p=$(cat "/sys/class/net/$IFACE/statistics/rx_packets" 2>/dev/null || echo 0)
    tx_p=$(cat "/sys/class/net/$IFACE/statistics/tx_packets" 2>/dev/null || echo 0)
    echo "frp-gre: $IFACE UP — local $LOCAL_PRIVATE_IP  peer $REMOTE_PRIVATE_IP  mtu $MTU  mss=$MSS_MODE  txq=$TXQUEUELEN  rx=${rx_p}p/${rx_b}B  tx=${tx_p}p/${tx_b}B"
}

case "${1:-}" in
    up|down|reload|hold|status) ;;
    *) usage ;;
esac
[[ $# -ge 2 ]] || usage
"cmd_$1" "$2"
ASSET_FRP_GRE
    then
        changed=1
    fi
    if sync_asset /etc/systemd/system/gre-tunnel@.service 0644 <<'ASSET_GRE_TUNNEL_SERVICE'
[Unit]
Description=GRE tunnel %i (FRP Tunnel Suite)
Documentation=file:///root/frp/gre/%i.env
StartLimitIntervalSec=0
StartLimitBurst=0
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/usr/local/bin/frp-gre up %i
ExecStart=/usr/local/bin/frp-gre hold %i
ExecReload=/usr/local/bin/frp-gre reload %i
ExecStop=/usr/local/bin/frp-gre down %i
Restart=always
RestartSec=2s
Nice=-10
OOMScoreAdjust=-900
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
ASSET_GRE_TUNNEL_SERVICE
    then
        changed=1
    fi
    if [[ -n "$changed" ]]; then
        systemctl daemon-reload
    fi
}

ensure_turbo_assets() {
    local changed=""
    if sync_asset /usr/local/bin/frp-turbo 0755 <<'ASSET_FRP_TURBO'
#!/bin/bash
# frp-turbo — persistent kernel/network tuning for the FRP Tunnel Suite.
# Applies BBR + fq + high-throughput / high-stability sysctls via a sysctl
# drop-in, ensures the frp GC cron, and manages optional ZRAM (lz4) +
# swappiness tuning. Conntrack tuning is applied only when conntrack is
# actually loaded, so the script never fails on hosts without it.
# Canonical copy: panel/internal/assets/helpers/frp-turbo (also embedded in frp-panel).
#
# Usage: frp-turbo apply|revert|status|zram-on|zram-off|zram-status|
#                   gc-cron|gc-status|volatile-logs|clear-logs
set -euo pipefail

SYSCTL_DROPIN="/etc/sysctl.d/99-tunnel-turbo.conf"
ZRAM_SYSCTL="/etc/sysctl.d/99-frp-zram.conf"
BBR_MODULE_FILE="/etc/modules-load.d/bbr.conf"
ZRAM_ENV="/etc/frp-panel/zram.env"
GC_CRON="0 */3 * * * pkill -10 -x frpc; pkill -10 -x frps"

usage() {
    echo "usage: frp-turbo apply|revert|status|zram-on|zram-off|zram-status|gc-cron|gc-status|volatile-logs|clear-logs" >&2
    exit 2
}

write_dropin() {
    mkdir -p /etc/sysctl.d
    cat > "$SYSCTL_DROPIN" <<'TURBO_SYSCTL'
# /etc/sysctl.d/99-tunnel-turbo.conf — FRP Tunnel Suite zero-drop tuning
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 1024
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6
net.ipv4.tcp_tw_reuse = 1
TURBO_SYSCTL

    # Only add the conntrack key when the table is actually available. Writing
    # an unknown key into the drop-in would make every later `sysctl --system`
    # fail on hosts that do not load nf_conntrack.
    if [[ -e /proc/sys/net/netfilter/nf_conntrack_max ]]; then
        echo "net.netfilter.nf_conntrack_max = 524288" >> "$SYSCTL_DROPIN"
    fi
}

ensure_gc_cron() {
    crontab -l 2>/dev/null | grep -Fq "$GC_CRON" && return 0
    (crontab -l 2>/dev/null; echo "$GC_CRON") | crontab -
}

cmd_apply() {
    mkdir -p /etc/modules-load.d
    write_dropin
    echo "tcp_bbr" > "$BBR_MODULE_FILE"
    modprobe tcp_bbr 2>/dev/null || true
    if ! sysctl --system >/dev/null; then
        echo "frp-turbo: warning: some sysctls could not be applied (kernel may not support them)" >&2
    fi
    # Undo the old (harmful) values at runtime: 16 KB tcp_notsent_lowat
    # starves YouTube/streaming bulk transfers on 40–100 ms links, and TCP
    # Fast Open payloads stall on Iranian ISP/DPI middleboxes.
    sysctl -w net.ipv4.tcp_notsent_lowat=4294967295 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.tcp_fastopen=0 >/dev/null 2>&1 || true
    ensure_gc_cron
    echo "frp-turbo: applied BBR + fq + stability sysctls ($SYSCTL_DROPIN); GC cron ensured"
    cmd_status
}

cmd_revert() {
    rm -f "$SYSCTL_DROPIN"
    sysctl --system >/dev/null 2>&1 || true
    echo "frp-turbo: removed $SYSCTL_DROPIN (kernel keeps current values until reboot)"
}

cmd_status() {
    local q cc bmss rmax wmax somax fwd ka ki kp reuse ct dropin
    q="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo '?')"
    cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '?')"
    bmss="$(sysctl -n net.ipv4.tcp_base_mss 2>/dev/null || echo '?')"
    rmax="$(sysctl -n net.core.rmem_max 2>/dev/null || echo '?')"
    wmax="$(sysctl -n net.core.wmem_max 2>/dev/null || echo '?')"
    somax="$(sysctl -n net.core.somaxconn 2>/dev/null || echo '?')"
    fwd="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '?')"
    ka="$(sysctl -n net.ipv4.tcp_keepalive_time 2>/dev/null || echo '?')"
    ki="$(sysctl -n net.ipv4.tcp_keepalive_intvl 2>/dev/null || echo '?')"
    kp="$(sysctl -n net.ipv4.tcp_keepalive_probes 2>/dev/null || echo '?')"
    reuse="$(sysctl -n net.ipv4.tcp_tw_reuse 2>/dev/null || echo '?')"
    ct="$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 'n/a')"
    [[ -f "$SYSCTL_DROPIN" ]] && dropin="installed" || dropin="missing"
    printf 'frp-turbo: qdisc=%s cc=%s tcp_base_mss=%s rmem_max=%s wmem_max=%s somaxconn=%s ip_forward=%s tcp_keepalive=%s/%s/%s tcp_tw_reuse=%s nf_conntrack_max=%s dropin=%s\n' \
        "$q" "$cc" "$bmss" "$rmax" "$wmax" "$somax" "$fwd" "$ka" "$ki" "$kp" "$reuse" "$ct" "$dropin"
}

cmd_zram_on() {
    mkdir -p /etc/frp-panel
    ZRAM_SIZE_MB=""; ZRAM_ALGO=""
    # shellcheck disable=SC1090
    [[ -r "$ZRAM_ENV" ]] && source "$ZRAM_ENV"
    ZRAM_SIZE_MB="${ZRAM_SIZE_MB:-2048}"
    ZRAM_ALGO="${ZRAM_ALGO:-lz4}"

    [[ -e /sys/block/zram0 ]] || modprobe zram
    [[ -e /sys/block/zram0 ]] || { echo "frp-turbo: zram module unavailable" >&2; exit 1; }

    if swapon --noheadings --show=NAME 2>/dev/null | grep -q zram; then
        echo "frp-turbo: zram0 swap already active"
        return 0
    fi
    if ! grep -q "\b$ZRAM_ALGO\b" /sys/block/zram0/comp_algorithm 2>/dev/null; then
        echo "frp-turbo: algorithm '$ZRAM_ALGO' unavailable, falling back to lzo" >&2
        ZRAM_ALGO=lzo
    fi
    echo "$ZRAM_ALGO" > /sys/block/zram0/comp_algorithm
    echo $(( ZRAM_SIZE_MB * 1024 * 1024 )) > /sys/block/zram0/disksize
    mkswap /dev/zram0 >/dev/null
    swapon -p 100 /dev/zram0
    printf 'vm.swappiness = 10\n' > "$ZRAM_SYSCTL"
    sysctl --system >/dev/null 2>&1 || true
    echo "frp-turbo: zram0 swap on — ${ZRAM_SIZE_MB}MB ${ZRAM_ALGO}, priority 100, swappiness 10"
}

cmd_zram_off() {
    swapoff /dev/zram0 >/dev/null 2>&1 || true
    echo 1 > /sys/block/zram0/reset 2>/dev/null || true
    rm -f "$ZRAM_SYSCTL"
    sysctl --system >/dev/null 2>&1 || true
    echo "frp-turbo: zram0 swap off"
}

cmd_zram_status() {
    swapon --noheadings --show=NAME,SIZE,USED,PRIORITY 2>/dev/null | grep zram \
        || echo "frp-turbo: no zram swap active"
}

# ---- mikeesierrah utilities --------------------------------------------------

cmd_gc_cron() {
    ensure_gc_cron
    cmd_gc_status
}

cmd_gc_status() {
    if crontab -l 2>/dev/null | grep -Fq "$GC_CRON"; then
        echo "frp-turbo: gc-cron=active"
    else
        echo "frp-turbo: gc-cron=missing"
    fi
}

journald_set() { # journald_set KEY VALUE
    local key="$1" value="$2" file="/etc/systemd/journald.conf"
    mkdir -p /etc/systemd
    touch "$file"
    if grep -Eq "^[#[:space:]]*${key}=" "$file"; then
        sed -i "s|^[#[:space:]]*${key}=.*|${key}=${value}|" "$file"
    else
        printf '%s=%s\n' "$key" "$value" >> "$file"
    fi
}

cmd_volatile_logs() {
    # Reduce disk I/O: logs live in memory. rsyslog is optional on minimal
    # images, so a missing/disabled rsyslog is not an error.
    systemctl disable --now rsyslog >/dev/null 2>&1 || true
    journald_set Storage volatile
    journald_set SystemMaxUse 50M
    journald_set SystemKeepFree 5M
    systemctl restart systemd-journald
    echo "frp-turbo: journald volatile (Storage=volatile, SystemMaxUse=50M, SystemKeepFree=5M); rsyslog disabled"
}

cmd_clear_logs() {
    journalctl --vacuum-time=1s >/dev/null 2>&1 || true
    find /var/log -type f -name "*.log" -exec truncate -s 0 {} \; 2>/dev/null || true
    find /var/log -type f -name "*.log.*" -delete 2>/dev/null || true
    find /var/log -type f \( -name "*.gz" -o -name "*.1" -o -name "*.2" -o -name "*.3" \
        -o -name "*.4" -o -name "*.5" -o -name "*.6" -o -name "*.7" -o -name "*.8" \
        -o -name "*.9" \) -delete 2>/dev/null || true
    truncate -s 0 /var/log/wtmp 2>/dev/null || true
    truncate -s 0 /var/log/btmp 2>/dev/null || true
    echo "frp-turbo: system logs cleared (journal vacuumed, rotated logs removed)"
}

case "${1:-}" in
    apply) cmd_apply ;;
    revert) cmd_revert ;;
    status) cmd_status ;;
    zram-on) cmd_zram_on ;;
    zram-off) cmd_zram_off ;;
    zram-status) cmd_zram_status ;;
    gc-cron) cmd_gc_cron ;;
    gc-status) cmd_gc_status ;;
    volatile-logs) cmd_volatile_logs ;;
    clear-logs) cmd_clear_logs ;;
    *) usage ;;
esac
ASSET_FRP_TURBO
    then
        changed=1
    fi
    if sync_asset /etc/systemd/system/tunnel-turbo.service 0644 <<'ASSET_TUNNEL_TURBO_SERVICE'
[Unit]
Description=FRP Tunnel Suite Turbo (BBR + fq + sysctl tuning)
Documentation=file:///usr/local/bin/frp-turbo
After=systemd-modules-load.service
Wants=systemd-modules-load.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/frp-turbo apply
ExecStop=/usr/local/bin/frp-turbo revert

[Install]
WantedBy=multi-user.target
ASSET_TUNNEL_TURBO_SERVICE
    then
        changed=1
    fi
    if sync_asset /etc/systemd/system/frp-zram.service 0644 <<'ASSET_FRP_ZRAM_SERVICE'
[Unit]
Description=FRP Tunnel Suite ZRAM swap
Documentation=file:///usr/local/bin/frp-turbo
After=systemd-modules-load.service
Wants=systemd-modules-load.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/frp-turbo zram-on
ExecStop=/usr/local/bin/frp-turbo zram-off

[Install]
WantedBy=multi-user.target
ASSET_FRP_ZRAM_SERVICE
    then
        changed=1
    fi
    if [[ -n "$changed" ]]; then
        systemctl daemon-reload
    fi
}

ensure_watchdog_assets() {
    local changed=""
    if sync_asset /usr/local/bin/frp-watchdog 0755 <<'ASSET_FRP_WATCHDOG'
#!/bin/bash
# frp-watchdog — dual-layer auto-heal for GRE links and FRP sessions.
# Runs as frp-watchdog.service; heals with a failure threshold + cooldown so a
# flapping link never causes a restart storm. Events go to the journal (stdout)
# and to /var/log/frp-panel/watchdog.log for the panel to surface.
#
# Layer 1 (GRE):  ping each peer through its gtXX interface. After THRESHOLD
#                 consecutive failures restart gre-tunnel@<iface>, then restart
#                 every active frpc@* unit so FRP reconnects over the new path.
# Layer 2 (FRP):  for every active frpc@*, test serverAddr:serverPort and, when
#                 its loopback webServer is enabled, verify every proxy reports
#                 "running" in /api/status. If GRE is healthy but these fail
#                 THRESHOLD times, restart only that frpc@ unit.
#
# Config: /etc/frp-panel/watchdog.env
#   INTERVAL=15  THRESHOLD=3  COOLDOWN=60  PING_TIMEOUT=2  TCP_TIMEOUT=3
#   TG_BOT_TOKEN=  TG_CHAT_ID=  TG_API_BASE=https://api.telegram.org
# Telegram alerts are optional; both TG_BOT_TOKEN and TG_CHAT_ID must be set.
# TG_API_BASE can point at a Cloudflare Worker reverse proxy on blocked hosts.
# Canonical copy: panel/internal/assets/helpers/frp-watchdog (also embedded in frp-panel).
set -uo pipefail   # deliberately NOT set -e: probe failures must not kill the loop

CONF="/etc/frp-panel/watchdog.env"
ENV_DIR="/root/frp/gre"
CLIENT_DIR="/root/frp/client"
LOG_DIR="/var/log/frp-panel"
STATE_DIR="/var/lib/frp-panel/watchdog"

INTERVAL=15; THRESHOLD=3; COOLDOWN=60; PING_TIMEOUT=2; TCP_TIMEOUT=3
TG_BOT_TOKEN=""; TG_CHAT_ID=""; TG_API_BASE="https://api.telegram.org"
# shellcheck disable=SC1090
[[ -r "$CONF" ]] && source "$CONF"

mkdir -p "$LOG_DIR" "$STATE_DIR"

declare -A GRE_OK=()
GRE_HEALTHY=1

log() {
    local line
    line="$(date -Is) frp-watchdog: $*"
    echo "$line" >> "$LOG_DIR/watchdog.log" 2>/dev/null || true
    echo "$line"
}

tg_notify() { # tg_notify <layer> <unit> <reason> <consecutive> <result>
    [[ -n "${TG_BOT_TOKEN:-}" && -n "${TG_CHAT_ID:-}" ]] || return 0
    local layer="$1" unit="$2" reason="$3" consec="$4" result="$5"
    case "$layer" in
        gre|GRE) layer="GRE" ;;
        frp|FRP) layer="FRP" ;;
    esac
    # Best-effort and strictly off the critical path: the watchdog loop never
    # waits for Telegram, even when the API is slow, blocked or unreachable.
    (
        local base="${TG_API_BASE:-https://api.telegram.org}"
        base="${base%/}"
        local host text
        host="$(hostname 2>/dev/null || echo unknown-host)"
        text="$(printf 'FRP Tunnel Suite heal event\nHost: %s\nLayer: %s\nUnit: %s\nReason: %s\nConsecutive failures: %s\nResult: %s' \
            "$host" "$layer" "$unit" "$reason" "$consec" "$result")"
        if ! curl -fsS --max-time 5 \
            --data-urlencode "chat_id=${TG_CHAT_ID}" \
            --data-urlencode "text=${text}" \
            --data-urlencode "disable_web_page_preview=true" \
            "${base}/bot${TG_BOT_TOKEN}/sendMessage" >/dev/null 2>&1; then
            printf '%s frp-watchdog: TELEGRAM delivery failed layer=%s unit=%s\n' \
                "$(date -Is)" "$layer" "$unit" >> "$LOG_DIR/watchdog.log" 2>/dev/null || true
        fi
    ) </dev/null >/dev/null 2>&1 &
}

fail_bump() { # fail_bump <key> ok|fail — echoes current consecutive-failure count
    local f="$STATE_DIR/$1.fails"
    if [[ "${2:-}" == "ok" ]]; then
        [[ -e "$f" ]] && echo 0 > "$f"
        echo 0
        return
    fi
    local c
    c=$(( $(cat "$f" 2>/dev/null || echo 0) + 1 ))
    echo "$c" > "$f"
    echo "$c"
}

in_cooldown() { # in_cooldown <key>
    local now last f="$STATE_DIR/$1.last"
    now=$(date +%s)
    last=$(cat "$f" 2>/dev/null || echo 0)
    (( now - last < COOLDOWN ))
}

heal() { # heal <unit> <key> <reason> [layer] [consecutive] — 0 when restarted
    local unit="$1" key="$2" reason="$3" layer="${4:-gre}" consec="${5:-?}"
    if in_cooldown "$key"; then
        log "SKIP layer=$layer unit=$unit reason=\"$reason\" cooldown=${COOLDOWN}s remaining"
        return 1
    fi
    date +%s > "$STATE_DIR/$key.last"
    if systemctl restart "$unit" 2>/dev/null; then
        log "HEAL action=restart layer=$layer unit=$unit reason=\"$reason\" consecutive=$consec result=ok"
        tg_notify "$layer" "$unit" "$reason" "$consec" "ok"
        echo 0 > "$STATE_DIR/$key.fails"
        return 0
    fi
    log "HEAL action=restart layer=$layer unit=$unit reason=\"$reason\" consecutive=$consec result=failed"
    tg_notify "$layer" "$unit" "$reason" "$consec" "fail"
    return 1
}

ping_ok() { # ping_ok <ip> [iface]
    local flags=(-c1 -W"$PING_TIMEOUT")
    if [[ "$1" == *:* ]]; then flags+=(-6); else flags+=(-4); fi
    [[ -n "${2:-}" ]] && flags+=(-I "$2")
    ping "${flags[@]}" "$1" >/dev/null 2>&1
}

ping_ok_tunnel() { # upgrade probe: 2 packets through the GRE interface
    local peer="$1" iface="$2"
    local flags=(-c2 -W"$PING_TIMEOUT")
    if [[ "$peer" == *:* ]]; then flags+=(-6); else flags+=(-4); fi
    ping "${flags[@]}" -I "$iface" "$peer" >/dev/null 2>&1
}

tcp_ok() { # tcp_ok <host> <port>
    timeout "$TCP_TIMEOUT" bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1
}

client_endpoint() { # client_endpoint <cfg> — echoes "addr port" (may be empty)
    local addr port
    addr=$(sed -n 's/^serverAddr *= *"\(.*\)"$/\1/p' "$1" | head -n1)
    port=$(sed -n 's/^serverPort *= *\([0-9][0-9]*\)$/\1/p' "$1" | head -n1)
    echo "$addr $port"
}

is_loopback_addr() {
    case "${1:-}" in
        127.*|localhost|::1|"[::1]") return 0 ;;
        *) return 1 ;;
    esac
}

frp_proxies_running() { # <cfg>; 0 healthy, 1 unhealthy, 2 no loopback webServer
    local cfg="$1" addr port user pass body total running url
    addr=$(sed -n 's/^webServer.addr *= *"\(.*\)"$/\1/p' "$cfg" | head -n1)
    port=$(sed -n 's/^webServer.port *= *\([0-9][0-9]*\)$/\1/p' "$cfg" | head -n1)
    [[ -n "$port" ]] || return 2
    [[ -n "$addr" ]] || addr="127.0.0.1"
    is_loopback_addr "$addr" || return 2
    command -v curl >/dev/null 2>&1 || return 2

    user=$(sed -n 's/^webServer.user *= *"\(.*\)"$/\1/p' "$cfg" | head -n1)
    pass=$(sed -n 's/^webServer.password *= *"\(.*\)"$/\1/p' "$cfg" | head -n1)
    local host="$addr"
    [[ "$addr" == *:* ]] && host="[${addr}]"
    url="http://${host}:${port}/api/status"

    if [[ -n "$user" ]]; then
        body=$(curl -fsS --max-time "$TCP_TIMEOUT" -u "${user}:${pass}" "$url" 2>/dev/null) || return 1
    else
        body=$(curl -fsS --max-time "$TCP_TIMEOUT" "$url" 2>/dev/null) || return 1
    fi
    [[ -n "$body" ]] || return 1

    total=$(grep -o '"status"[[:space:]]*:' <<<"$body" | wc -l | tr -d ' ')
    running=$(grep -o '"status"[[:space:]]*:[[:space:]]*"running"' <<<"$body" | wc -l | tr -d ' ')
    (( total > 0 && total == running ))
}

active_frpc_units() {
    systemctl list-units --type=service --state=running --plain --no-legend 'frpc@*.service' 2>/dev/null \
        | awk '$1 ~ /^frpc@/ { print $1 }'
}

restart_active_frpc() { # restart_active_frpc <reason>
    local unit
    for unit in $(active_frpc_units); do
        if systemctl restart "$unit" 2>/dev/null; then
            log "HEAL action=restart-frpc layer=gre unit=$unit reason=\"$1\" result=ok"
            tg_notify "GRE" "$unit" "$1" "after GRE rebuild" "ok"
        else
            log "HEAL action=restart-frpc layer=gre unit=$unit reason=\"$1\" result=failed"
            tg_notify "GRE" "$unit" "$1" "after GRE rebuild" "fail"
        fi
    done
}

check_gre() {
    local env fails peer
    GRE_HEALTHY=1
    GRE_OK=()
    for env in "$ENV_DIR"/*.env; do
        [[ -e "$env" ]] || return 0
        IFACE=""; REMOTE_PRIVATE_IP=""
        # shellcheck disable=SC1090
        source "$env"
        [[ -n "$IFACE" && -n "$REMOTE_PRIVATE_IP" ]] || continue
        peer="${REMOTE_PRIVATE_IP%%/*}"

        if ip link show "$IFACE" >/dev/null 2>&1 && ping_ok_tunnel "$peer" "$IFACE"; then
            fail_bump "gre-$IFACE" ok >/dev/null
            GRE_OK[$IFACE]=1
            continue
        fi

        GRE_OK[$IFACE]=0
        GRE_HEALTHY=0
        fails=$(fail_bump "gre-$IFACE" fail)
        if (( fails >= THRESHOLD )); then
            if heal "gre-tunnel@$IFACE.service" "gre-$IFACE" \
                    "$fails consecutive GRE probes to $peer via $IFACE failed" gre "$fails"; then
                restart_active_frpc "GRE $IFACE rebuilt after $fails failed probes"
            fi
        else
            log "GRE layer=1 iface=$IFACE status=degraded peer=$peer fails=$fails/$THRESHOLD"
        fi
    done
}

check_frpc() {
    local unit name cfg addr port fails reason mode
    # Layer 2 only makes sense once the GRE path is healthy (or no GRE exists).
    [[ "$GRE_HEALTHY" == "1" ]] || return 0

    for unit in $(active_frpc_units); do
        name="${unit#frpc@}"; name="${name%.service}"
        cfg="$CLIENT_DIR/$name.toml"
        [[ -r "$cfg" ]] || continue
        read -r addr port <<< "$(client_endpoint "$cfg")"
        [[ -n "$addr" && -n "$port" ]] || continue

        reason=""
        if ! tcp_ok "$addr" "$port"; then
            reason="control channel ${addr}:${port} unreachable"
        else
            frp_proxies_running "$cfg"
            mode=$?
            if (( mode == 1 )); then
                reason="webServer /api/status reports non-running proxies"
            fi
        fi

        if [[ -z "$reason" ]]; then
            fail_bump "frpc-$name" ok >/dev/null
            continue
        fi

        fails=$(fail_bump "frpc-$name" fail)
        if (( fails >= THRESHOLD )); then
            heal "$unit" "frpc-$name" "$reason ($fails consecutive checks)" frp "$fails" || true
        else
            log "FRP layer=2 unit=$unit status=degraded reason=\"$reason\" fails=$fails/$THRESHOLD"
        fi
    done
}

log "watchdog started (interval=${INTERVAL}s threshold=${THRESHOLD} cooldown=${COOLDOWN}s telegram=$([[ -n "${TG_BOT_TOKEN:-}" && -n "${TG_CHAT_ID:-}" ]] && echo on || echo off))"
while true; do
    check_gre
    check_frpc
    sleep "$INTERVAL"
done
ASSET_FRP_WATCHDOG
    then
        changed=1
    fi
    if sync_asset /etc/systemd/system/frp-watchdog.service 0644 <<'ASSET_FRP_WATCHDOG_SERVICE'
[Unit]
Description=FRP Tunnel Suite Watchdog (dual-layer auto-heal: GRE + frpc)
Documentation=file:///usr/local/bin/frp-watchdog
StartLimitIntervalSec=0
StartLimitBurst=0
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/frp-watchdog
Restart=always
RestartSec=2s
Nice=-5
OOMScoreAdjust=-500

[Install]
WantedBy=multi-user.target
ASSET_FRP_WATCHDOG_SERVICE
    then
        changed=1
    fi
    if [[ -n "$changed" ]]; then
        systemctl daemon-reload
    fi
}

ensure_panel_unit() {
    if sync_asset /etc/systemd/system/frp-panel.service 0644 <<'ASSET_FRP_PANEL_SERVICE'
[Unit]
Description=FRP Tunnel Suite Web Panel
Documentation=https://gofrp.org/en/docs/overview/
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/frp-panel serve --config /etc/frp-panel/panel.toml
Restart=always
RestartSec=5
LimitNOFILE=65535

# Hardening: root is required for /root/frp, systemctl, ip and sysctl,
# everything else is locked down as far as systemd allows.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/root/frp /etc/frp-panel /etc/sysctl.d /etc/systemd/system /usr/local/bin /var/log/frp-panel
RestrictSUIDSGID=yes

[Install]
WantedBy=multi-user.target
ASSET_FRP_PANEL_SERVICE
    then
        systemctl daemon-reload
    fi
}

# --- v1 compatibility: light silent ensure (cron GC + BBR/fq) -----------------
# Kept as `optimize` so the original self-install sed trick keeps working.
# Full tuning is applied by tunnel-turbo.service (menu 7 / turbo apply).
optimize() {
    local -r cron_job="0 */3 * * * pkill -10 -x frpc; pkill -10 -x frps"
    local -r bbr_conf="/etc/sysctl.d/99-bbr-ensure.conf"

    # Ensure cron job exists (idempotent) — unchanged from v1
    sudo crontab -l 2>/dev/null | grep -Fq "${cron_job}" || {
        (sudo crontab -l 2>/dev/null; echo "${cron_job}") | sudo crontab -
    }

    # Configure BBR if not already optimal — unchanged behaviour, but via a
    # drop-in file instead of appending to /etc/sysctl.conf
    [[ "$(sysctl -n net.core.default_qdisc)" == "fq" &&
       "$(sysctl -n net.ipv4.tcp_congestion_control)" == "bbr" ]] && return

    echo "tcp_bbr" | sudo tee /etc/modules-load.d/bbr.conf >/dev/null
    sudo modprobe tcp_bbr 2>/dev/null || true
    printf 'net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n' | sudo tee "$bbr_conf" >/dev/null
    sudo sysctl --system >/dev/null
}

# --- Turbo -------------------------------------------------------------------

turbo_apply() {
    ensure_turbo_assets
    systemctl enable tunnel-turbo >/dev/null 2>&1 || true
    systemctl restart tunnel-turbo
    print_success "Tunnel Turbo applied persistently (tunnel-turbo.service)."
}

turbo_revert() {
    systemctl disable --now tunnel-turbo >/dev/null 2>&1 || true
    /usr/local/bin/frp-turbo revert 2>/dev/null || true
    print_success "Tunnel Turbo reverted (drop-in removed)."
}

zram_on() { # zram_on SIZE_MB ALGO
    mkdir -p "$PANEL_CONF_DIR"
    printf 'ZRAM_SIZE_MB=%s\nZRAM_ALGO=%s\n' "$1" "$2" > "$PANEL_CONF_DIR/zram.env"
    ensure_turbo_assets
    systemctl enable frp-zram >/dev/null 2>&1 || true
    systemctl restart frp-zram
    print_success "ZRAM enabled (${1}MB ${2}, priority 100, swappiness 10)."
}

zram_off() {
    systemctl disable --now frp-zram >/dev/null 2>&1 || true
    /usr/local/bin/frp-turbo zram-off 2>/dev/null || true
    print_success "ZRAM disabled."
}

# Reduce I/O by disabling rsyslog and making journald volatile (canonical
# helper: idempotent journald.conf edit + restart).
reduce_io() {
    print_info "Reducing I/O by logging only to memory..."
    ensure_turbo_assets
    /usr/local/bin/frp-turbo volatile-logs
    print_success "I/O reduced - logs are now stored in volatile memory."
}

# Remove all system logs (canonical helper: journal vacuum, truncate, rotate).
remove_logs() {
    print_warning "This will permanently delete all system logs!"
    read -p "Are you sure you want to continue? (yes/no): " confirm

    if [[ "$confirm" != "yes" ]]; then
        print_info "Log removal cancelled."
        return
    fi

    ensure_turbo_assets
    /usr/local/bin/frp-turbo clear-logs
    print_success "All system logs have been removed."
}

# Idempotent 3h FRP GC cron (pkill -10 triggers Go GC, keeps connections).
gc_cron() {
    ensure_turbo_assets
    /usr/local/bin/frp-turbo gc-cron
    print_success "FRP GC cron (every 3h) is installed."
}

# Utilities menu (item 7 — same slot as v1, now Turbo-aware)
utilities_menu() {
    while true; do
        clear
        print_header
        echo "Optimization Utilities (Turbo)"
        echo "------------------------------"
        echo
        echo "1) Apply Full Turbo (BBR + fq + sysctl service, persistent)"
        echo "2) Configure ZRAM (default 2048MB lz4)"
        echo "3) OS logs Only In Memory (Reduce disk I/O)"
        echo "4) Remove All System logs (Clears Storage)"
        echo "5) Install / verify FRP GC cron (every 3h)"
        echo "6) Back to Main Menu"
        echo

        read -p "Choose an option [1-6]: " util_choice
        echo

        case $util_choice in
            1)
                turbo_apply
                pause
                ;;
            2)
                read -p "Enable ZRAM? (y/n) [y]: " zr
                if [[ "$zr" =~ ^[Yy]?$ ]]; then
                    read -p "ZRAM size in MB [2048]: " zsize
                    zsize=${zsize:-2048}
                    read -p "Compression algorithm (lz4/lzo/zstd) [lz4]: " zalgo
                    zalgo=${zalgo:-lz4}
                    zram_on "$zsize" "$zalgo"
                else
                    zram_off
                fi
                pause
                ;;
            3)
                reduce_io
                pause
                ;;
            4)
                remove_logs
                pause
                ;;
            5)
                gc_cron
                pause
                ;;
            6)
                return
                ;;
            *)
                print_error "Invalid option. Please choose 1-6."
                pause
                ;;
        esac
    done
}

# --- Self-install (v1 behavior; installs THIS file, not a stale upstream) -----
install_script() {
    if [[ "$SCRIPT_PATH" == "$INSTALL_PATH" ]]; then
        print_info "Script is already installed as frp-manager command."
        return
    fi

    print_info "Installing script as frp-manager command..."
    if [[ -n "$FRP_SETUP_SOURCE_URL" ]]; then
        curl -L "$FRP_SETUP_SOURCE_URL" -o "$INSTALL_PATH"
    else
        cp "$SCRIPT_PATH" "$INSTALL_PATH"
    fi
    sudo chmod +x "$INSTALL_PATH"

    # Comment out the call to install_script in the installed version
    sed -i 's/^install_script$/# install_script/' "$INSTALL_PATH"

    # Comment out the call to optimize in the installed version
    sed -i 's/^optimize$/# optimize/' "$INSTALL_PATH"

    print_success "Script installed as frp-manager. You can now run it by typing 'frp-manager' in terminal."
}

# --- Install FRP (v1 flow; units now come from the canonical assets) ---------
install_frp() {
    print_info "Starting FRP installation..."

    # Detect platform
    arch=$(uname -m)
    case "$arch" in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv7l|armv6l) arch="arm" ;;
        *) print_error "Unsupported arch: $arch"; exit 1 ;;
    esac

    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    platform="${os}_${arch}"

    # Get latest version
    print_info "Fetching latest FRP version..."
    version=$(curl -s https://api.github.com/repos/fatedier/frp/releases/latest | grep tag_name | cut -d '"' -f4 | sed 's/v//')
    url="https://github.com/fatedier/frp/releases/download/v${version}/frp_${version}_${platform}.tar.gz"

    print_info "Downloading $url"
    curl -L "$url" -o "/tmp/frp.tar.gz"

    print_info "Extracting..."
    tar -xzf /tmp/frp.tar.gz -C /tmp

    print_info "Installing frpc and frps..."
    cp /tmp/frp_${version}_${platform}/frpc /usr/local/bin/
    cp /tmp/frp_${version}_${platform}/frps /usr/local/bin/
    chmod +x /usr/local/bin/frpc /usr/local/bin/frps

    print_info "Creating config folders..."
    mkdir -p /root/frp/server
    mkdir -p /root/frp/client

    print_info "Writing frps@.service..."
    cat > /etc/systemd/system/frps@.service <<'ASSET_FRPS_SERVICE'
[Unit]
Description=FRP Server Service (%i)
Documentation=https://gofrp.org/en/docs/overview/
StartLimitIntervalSec=0
StartLimitBurst=0
After=network.target nss-lookup.target network-online.target
Wants=network-online.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
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

    print_info "Writing frpc@.service..."
    cat > /etc/systemd/system/frpc@.service <<'ASSET_FRPC_SERVICE'
[Unit]
Description=FRP Client Service (%i)
Documentation=https://gofrp.org/en/docs/overview/
StartLimitIntervalSec=0
StartLimitBurst=0
After=network.target nss-lookup.target network-online.target
Wants=network-online.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE CAP_NET_BIND_SERVICE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
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

    print_info "Reloading systemd..."
    systemctl daemon-reload

    print_success "FRP $version installed and services created."
}

# --- Setup FRP Server (upgraded: bindAddr choice, auto token, webServer) ------
setup_server() {
    print_info "FRP Server Setup"

    read -p "Enter bindPort [7000]: " bindPort
    bindPort=${bindPort:-7000}
    if ! is_valid_port "$bindPort"; then
        print_error "Invalid port."
        return 1
    fi

    echo "Enable Quic or KCP ? (default = 2):"
    echo "  1) none"
    echo "  2) quic"
    echo "  3) kcp"
    read -p "Protocol [1]: " proto_choice
    proto_choice=${proto_choice:-1}

    read -p "Enable TCP Mux (y/n) [n]: " use_mux
    use_mux=${use_mux:-n}

    # NEW: bind address (private tunnel IP support)
    echo "Bind address:"
    echo "  1) ::                (dual-stack — default)"
    echo "  2) 0.0.0.0           (IPv4 only)"
    echo "  3) Private tunnel IP (bind frps inside a GRE tunnel, e.g. 10.100.111.2)"
    local priv_hint
    priv_hint=$(ip -o -4 addr show 2>/dev/null | awk '{print $4}' | grep -E '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' || true)
    if [[ -n "$priv_hint" ]]; then
        echo "      Private IPs on this host: $(echo "$priv_hint" | tr '\n' ' ')"
    fi
    read -p "Choice [1]: " addr_choice
    local bind_addr="::"
    case "$addr_choice" in
        2) bind_addr="0.0.0.0" ;;
        3)
            read -p "Private tunnel IP: " bind_addr
            if ! is_ipv4 "$bind_addr"; then
                print_error "Invalid IPv4 address."
                return 1
            fi
            if ! ip -o -4 addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -qx "$bind_addr"; then
                print_warning "$bind_addr is not present on any interface (is the GRE tunnel up?)"
                read -p "Continue anyway? (y/n) [y]: " cont
                if [[ ! "$cont" =~ ^[Yy]?$ ]]; then
                    print_info "Cancelled."
                    return 0
                fi
            fi
            ;;
        1|"") bind_addr="::" ;;
        *) print_error "Invalid choice."; return 1 ;;
    esac

    # NEW: auto token generator (replaces the static v1 default)
    local generated_token token
    generated_token=$(gen_token)
    read -p "Auth token (empty = generate a strong random token): " token
    token=${token:-$generated_token}

    # NEW: metrics dashboard (FRP webServer) — powers stats in the Web Panel
    read -p "Enable FRP metrics dashboard (webServer)? (y/n) [y]: " want_dash
    want_dash=${want_dash:-y}
    local dash_port=""
    if [[ "$want_dash" =~ ^[Yy]$ ]]; then
        if ! dash_port=$(allocate_web_port 7500 7599 "$SERVER_DIR"); then
            print_error "No free webServer port in 7500-7599."
            return 1
        fi
    fi

    mkdir -p "$SERVER_DIR/"
    config="$SERVER_DIR/server-$bindPort.toml"

    print_info "Writing config to $config"

    {
        echo "# Generated by frp-suite (frp-manager CLI / frp-panel Web UI)"
        echo "bindAddr = \"$bind_addr\""
        echo "bindPort = $bindPort"
        # A private/GRE bindAddr would make frps bind the forwarded user ports
        # to that address only (unreachable publicly) — keep the control port
        # private but the forwarded ports on all interfaces.
        if [[ -n "$bind_addr" && "$bind_addr" != "0.0.0.0" && "$bind_addr" != "::" ]]; then
            echo "proxyBindAddr = \"0.0.0.0\""
        fi

        if [[ $proto_choice == 2 ]]; then
            echo "quicBindPort = $bindPort"
        elif [[ $proto_choice == 3 ]]; then
            echo "kcpBindPort = $bindPort"
        fi
        echo

        if [[ $proto_choice == 2 ]]; then
            echo "transport.quic.keepalivePeriod = 10"
            echo "transport.quic.maxIdleTimeout = 30"
            echo "transport.quic.maxIncomingStreams = 100000"
        else
            echo "# transport.quic.keepalivePeriod = 10"
            echo "# transport.quic.maxIdleTimeout = 30"
            echo "# transport.quic.maxIncomingStreams = 100000"
        fi
        echo

        echo "transport.heartbeatTimeout = 90"
        echo "transport.maxPoolCount = 65535"
        echo "transport.tcpMux = $( [[ $use_mux =~ ^[Yy]$ ]] && echo true || echo false )"
        echo "transport.tcpMuxKeepaliveInterval = 10"
        echo "transport.tcpKeepalive = 120"
        echo
        echo "auth.method = \"token\""
        echo "auth.token = \"$token\""
        if [[ -n "$dash_port" ]]; then
            echo
            echo "webServer.addr = \"127.0.0.1\""
            echo "webServer.port = $dash_port"
            echo "webServer.user = \"admin\""
            echo "webServer.password = \"$(gen_token)\""
        fi
    } > "$config"
    chmod 600 "$config"

    print_info "Enabling and starting frps@server-$bindPort..."
    if systemctl is-active --quiet "frps@server-$bindPort" 2>/dev/null; then
        systemctl restart "frps@server-$bindPort"
    else
        systemctl enable --now "frps@server-$bindPort"
    fi

    print_success "Server setup complete."
    echo
    print_warning "Auth token (the client must use the SAME token): $token"
    if [[ -n "$dash_port" ]]; then
        print_info "Metrics dashboard: http://127.0.0.1:$dash_port (admin / see $config)"
    fi
}

# --- Port expansion helpers ---------------------------------------------------

# expand_port_input "22,6000-6006" -> PORT_LIST array + EXPANDED_COUNT
expand_port_input() {
    local input="$1" part start end p
    local -a parts=()
    local -A seen=()
    PORT_LIST=()
    IFS=',' read -r -a parts <<< "$input"
    for part in "${parts[@]}"; do
        part="${part// /}"
        [[ -z "$part" ]] && continue
        if [[ "$part" == *-* ]]; then
            start="${part%-*}"
            end="${part#*-}"
        else
            start="$part"
            end="$part"
        fi
        for p in $(seq "$start" "$end"); do
            if ! is_valid_port "$p"; then
                print_error "Invalid port '$p' in '$part'."
                return 1
            fi
            if [[ -n "${seen[$p]:-}" ]]; then
                print_error "Port $p appears more than once in the input."
                return 1
            fi
            seen[$p]=1
            PORT_LIST+=("$p")
        done
    done
    EXPANDED_COUNT=${#PORT_LIST[@]}
    if (( EXPANDED_COUNT == 0 )); then
        print_error "No ports given."
        return 1
    fi
}

# proxy_block TYPE PORT — one [[proxies]] block to stdout (uses enc/comp globals)
proxy_block() {
    echo
    echo "[[proxies]]"
    echo "name = \"$1-$2\""
    echo "type = \"$1\""
    echo "localIP = \"127.0.0.1\""
    echo "localPort = $2"
    echo "remotePort = $2"
    echo "transport.useEncryption = $enc_enabled"
    echo "transport.useCompression = $compression_enabled"
}

# --- Setup FRP Client (upgraded: secure defaults, dual TCP+UDP, naming) -------
setup_client() {
    print_info "FRP Client Setup"

    read -p "Server IP (v4 or v6): " server_ip
    if [[ -z "$server_ip" ]]; then
        print_error "Server IP is required."
        return 1
    fi

    read -p "Server port [7000]: " server_port
    server_port=${server_port:-7000}
    if ! is_valid_port "$server_port"; then
        print_error "Invalid port."
        return 1
    fi

    # NEW: token — default to the matching local server config's token
    local def_token="" local_server auth_token=""
    local_server="$SERVER_DIR/server-$server_port.toml"
    if [[ -r "$local_server" ]]; then
        def_token=$(sed -n 's/^auth.token *= *"\(.*\)"$/\1/p' "$local_server" | head -n1)
        if [[ -n "$def_token" ]]; then
            print_info "Local server config found ($local_server) — its token is the default."
        fi
    fi
    read -p "Auth token${def_token:+ [Enter = use local server token]}: " auth_token
    auth_token=${auth_token:-$def_token}
    while [[ -z "$auth_token" ]]; do
        read -p "Auth token (must match the server; 'g' generates one): " auth_token
        if [[ "$auth_token" == "g" ]]; then
            auth_token=$(gen_token)
            print_info "Generated token: $auth_token"
            print_warning "Set this SAME token on your frps server."
            break
        fi
    done

    echo "Choose transport protocol:"
    echo "1) tcp"
    echo "2) websocket"
    echo "3) quic"
    echo "4) kcp"
    read -p "Option [1]: " transport_option
    case $transport_option in
        2) transport="websocket" ;;
        3) transport="quic" ;;
        4) transport="kcp" ;;
        1|"") transport="tcp" ;;
        *) transport="tcp" ;;
    esac

    read -p "Enable TCP Mux (y/n) [n]: " use_mux
    use_mux=${use_mux:-n}
    mux=$([[ $use_mux =~ ^[Yy]$ ]] && echo true || echo false)

    print_warning "Warning: Enabling compression will significantly increase RAM usage"
    read -p "Enable Compression (y/n) [n]: " use_compression
    use_compression=${use_compression:-n}
    compression_enabled=$([[ $use_compression =~ ^[Yy]$ ]] && echo true || echo false)

    # mikeesierrah profile: TLS/encryption off by default (the tunnel/VPN
    # already encrypts); both remain toggleable.
    read -p "Enable TLS transport (y/n) [n]: " use_tls
    use_tls=${use_tls:-n}
    tls_enabled=$([[ $use_tls =~ ^[Yy]$ ]] && echo true || echo false)

    read -p "Enable per-proxy encryption (y/n) [n]: " use_enc
    use_enc=${use_enc:-n}
    enc_enabled=$([[ $use_enc =~ ^[Yy]$ ]] && echo true || echo false)

    # NEW: dual TCP+UDP forwarding toggle
    read -p "Also forward UDP for these ports? (y/n) [y]: " use_udp
    use_udp=${use_udp:-y}
    udp_enabled=$([[ $use_udp =~ ^[Yy]$ ]] && echo true || echo false)

    read -p "Local ports to expose (e.g. 22,6000-6006,6007): " port_input
    if [[ -z "$port_input" ]]; then
        print_error "Port list is required."
        return 1
    fi

    # NEW: collision-safe instance naming
    read -p "Instance name [client-$server_port]: " inst_name
    inst_name=${inst_name:-"client-$server_port"}
    if ! [[ "$inst_name" =~ ^[A-Za-z0-9_.-]{1,64}$ ]]; then
        print_error "Invalid instance name."
        return 1
    fi
    config="$CLIENT_DIR/$inst_name.toml"
    if [[ -f "$config" ]]; then
        print_warning "Config exists: $config"
        read -p "Overwrite (existing file will be backed up)? (y/n) [n]: " ow
        if [[ ! "$ow" =~ ^[Yy]$ ]]; then
            print_info "Cancelled."
            return 0
        fi
        cp -a "$config" "$config.bak-$(date +%Y%m%d-%H%M%S)"
    fi

    # NEW: metrics dashboard
    read -p "Enable FRP metrics dashboard (webServer)? (y/n) [y]: " want_dash
    want_dash=${want_dash:-y}
    local dash_port=""
    if [[ "$want_dash" =~ ^[Yy]$ ]]; then
        if ! dash_port=$(allocate_web_port 7400 7499 "$CLIENT_DIR"); then
            print_error "No free webServer port in 7400-7499."
            return 1
        fi
    fi

    mkdir -p "$CLIENT_DIR/"
    if ! expand_port_input "$port_input"; then
        return 1
    fi

    # Large ranges: keep files compact with frp's Go-template rendering (v1 trick)
    local mode="explicit"
    if (( EXPANDED_COUNT > 500 )); then
        if [[ "${NONINT:-}" == "1" ]]; then
            mode="template"
        else
            read -p "$EXPANDED_COUNT ports — use compact template mode? (y/n) [y]: " tpl
            if [[ "$tpl" =~ ^[Yy]?$ ]]; then
                mode="template"
            fi
        fi
    fi

    print_info "Writing config to $config"
    if [[ "$mode" == "template" ]]; then
        cat > "$config" <<EOF
# Generated by frp-suite (frp-manager CLI / frp-panel Web UI) — compact template mode
serverAddr = "$server_ip"
serverPort = $server_port

loginFailExit = false

auth.method = "token"
auth.token = "$auth_token"

transport.protocol = "$transport"
transport.tcpMux = $mux
transport.tcpMuxKeepaliveInterval = 10
transport.dialServerTimeout = 10
transport.dialServerKeepalive = 120
transport.poolCount = 20
transport.heartbeatInterval = 30
transport.heartbeatTimeout = 90
transport.tls.enable = $tls_enabled
transport.quic.keepalivePeriod = 10
transport.quic.maxIdleTimeout = 30
transport.quic.maxIncomingStreams = 100000

{{- range \$_, \$v := parseNumberRangePair "$port_input" "$port_input" }}
[[proxies]]
name = "tcp-{{ \$v.First }}"
type = "tcp"
localIP = "127.0.0.1"
localPort = {{ \$v.First }}
remotePort = {{ \$v.Second }}
transport.useEncryption = $enc_enabled
transport.useCompression = $compression_enabled
{{- end }}
EOF
        if [[ "$udp_enabled" == "true" ]]; then
            cat >> "$config" <<EOF

{{- range \$_, \$v := parseNumberRangePair "$port_input" "$port_input" }}
[[proxies]]
name = "udp-{{ \$v.First }}"
type = "udp"
localIP = "127.0.0.1"
localPort = {{ \$v.First }}
remotePort = {{ \$v.Second }}
transport.useEncryption = $enc_enabled
transport.useCompression = $compression_enabled
{{- end }}
EOF
        fi
    else
        {
            echo "# Generated by frp-suite (frp-manager CLI / frp-panel Web UI)"
            echo "serverAddr = \"$server_ip\""
            echo "serverPort = $server_port"
            echo
            echo "loginFailExit = false"
            echo
            echo "auth.method = \"token\""
            echo "auth.token = \"$auth_token\""
            echo
            echo "transport.protocol = \"$transport\""
            echo "transport.tcpMux = $mux"
            echo "transport.tcpMuxKeepaliveInterval = 10"
            echo "transport.dialServerTimeout = 10"
            echo "transport.dialServerKeepalive = 120"
            echo "transport.poolCount = 20"
            echo "transport.heartbeatInterval = 30"
            echo "transport.heartbeatTimeout = 90"
            echo "transport.tls.enable = $tls_enabled"
            echo "transport.quic.keepalivePeriod = 10"
            echo "transport.quic.maxIdleTimeout = 30"
            echo "transport.quic.maxIncomingStreams = 100000"
            for p in "${PORT_LIST[@]}"; do
                proxy_block "tcp" "$p"
                if [[ "$udp_enabled" == "true" ]]; then
                    proxy_block "udp" "$p"
                fi
            done
        } > "$config"
    fi

    if [[ -n "$dash_port" ]]; then
        {
            echo
            echo "webServer.addr = \"127.0.0.1\""
            echo "webServer.port = $dash_port"
            echo "webServer.user = \"admin\""
            echo "webServer.password = \"$(gen_token)\""
        } >> "$config"
    fi
    chmod 600 "$config"

    print_info "Enabling and starting frpc@$inst_name..."
    if systemctl is-active --quiet "frpc@$inst_name" 2>/dev/null; then
        systemctl restart "frpc@$inst_name"
    else
        systemctl enable --now "frpc@$inst_name"
    fi

    local n_tcp=0 n_udp=0
    if [[ "$udp_enabled" == "true" ]]; then n_udp=$EXPANDED_COUNT; fi
    n_tcp=$EXPANDED_COUNT
    print_success "Client setup complete: $n_tcp TCP$( [[ "$udp_enabled" == "true" ]] && printf ' + %d UDP' "$n_udp" ) proxies, tls=$tls_enabled, encryption=$enc_enabled."
}

# --- Advanced config management (v1, unchanged) --------------------------------
advanced_config() {
    print_info "Advanced Configuration Management"
    echo
    echo "1) Server Configuration"
    echo "2) Client Configuration"
    echo "3) Back to main menu"
    echo
    read -p "Choose option [1-3]: " config_choice

    case $config_choice in
        1)
            if [[ ! -d "/root/frp/server" ]] || [[ -z "$(ls -A /root/frp/server/ 2>/dev/null)" ]]; then
                print_warning "No server configurations found in /root/frp/server/"
                return
            fi

            print_info "Available server configurations:"
            echo
            local configs=()
            mapfile -t configs < <(find /root/frp/server -maxdepth 1 -type f -name '*.toml' -printf '%f\n' 2>/dev/null | sort)
            for i in "${!configs[@]}"; do
                echo "$((i+1))) ${configs[$i]}"
            done
            echo "$((${#configs[@]}+1))) Back"
            echo

            read -p "Select configuration to edit [1-$((${#configs[@]}+1))]: " server_choice

            if [[ $server_choice -eq $((${#configs[@]}+1)) ]]; then
                return
            elif [[ $server_choice -ge 1 && $server_choice -le ${#configs[@]} ]]; then
                selected_config="${configs[$((server_choice-1))]}"
                config_path="/root/frp/server/$selected_config"

                print_info "Current configuration ($selected_config):"
                echo "----------------------------------------"
                cat "$config_path"
                echo "----------------------------------------"
                echo

                read -p "Edit this file? (y/n) [n]: " edit_choice
                if [[ "$edit_choice" =~ ^[Yy]$ ]]; then
                    ${EDITOR:-nano} "$config_path"

                    # Restart service if it's running
                    service_name="${selected_config%.toml}"
                    if systemctl is-active --quiet "frps@$service_name"; then
                        print_info "Restarting service frps@$service_name..."
                        systemctl restart "frps@$service_name"
                        print_success "Service restarted."
                    fi
                fi
            fi
            ;;
        2)
            if [[ ! -d "/root/frp/client" ]] || [[ -z "$(ls -A /root/frp/client/ 2>/dev/null)" ]]; then
                print_warning "No client configurations found in /root/frp/client/"
                return
            fi

            print_info "Available client configurations:"
            echo
            local configs=()
            mapfile -t configs < <(find /root/frp/client -maxdepth 1 -type f -name '*.toml' -printf '%f\n' 2>/dev/null | sort)
            for i in "${!configs[@]}"; do
                echo "$((i+1))) ${configs[$i]}"
            done
            echo "$((${#configs[@]}+1))) Back"
            echo

            read -p "Select configuration to edit [1-$((${#configs[@]}+1))]: " client_choice

            if [[ $client_choice -eq $((${#configs[@]}+1)) ]]; then
                return
            elif [[ $client_choice -ge 1 && $client_choice -le ${#configs[@]} ]]; then
                selected_config="${configs[$((client_choice-1))]}"
                config_path="/root/frp/client/$selected_config"

                print_info "Current configuration ($selected_config):"
                echo "----------------------------------------"
                cat "$config_path"
                echo "----------------------------------------"
                echo

                read -p "Edit this file? (y/n) [n]: " edit_choice
                if [[ "$edit_choice" =~ ^[Yy]$ ]]; then
                    ${EDITOR:-nano} "$config_path"

                    # Restart service if it's running
                    service_name="${selected_config%.toml}"
                    if systemctl is-active --quiet "frpc@$service_name"; then
                        print_info "Restarting service frpc@$service_name..."
                        systemctl restart "frpc@$service_name"
                        print_success "Service restarted."
                    fi
                fi
            fi
            ;;
        3)
            return
            ;;
        *)
            print_error "Invalid option"
            ;;
    esac
}

# --- Stop services (v1, unchanged) -------------------------------------------
stop_services() {
    print_info "Stopping FRP services..."

    # Stop all running frps services
    running_servers=$(systemctl list-units --type=service --state=running | grep "frps@" | awk '{print $1}' || true)
    if [[ -n "$running_servers" ]]; then
        print_info "Stopping server services..."
        for service in $running_servers; do
            print_info "Stopping $service..."
            systemctl stop "$service"
        done
    fi

    # Stop all running frpc services
    running_clients=$(systemctl list-units --type=service --state=running | grep "frpc@" | awk '{print $1}' || true)
    if [[ -n "$running_clients" ]]; then
        print_info "Stopping client services..."
        for service in $running_clients; do
            print_info "Stopping $service..."
            systemctl stop "$service"
        done
    fi

    print_success "All FRP services stopped."
}

# --- Remove FRP (v1 flow + optional suite-component removal) ------------------
remove_frp() {
    print_warning "This will completely remove FRP and all configurations!"
    read -p "Are you sure? (yes/no): " confirm

    if [[ "$confirm" != "yes" ]]; then
        print_info "Removal cancelled."
        return
    fi

    print_info "Stopping all FRP services..."
    stop_services

    print_info "Disabling and removing services..."
    # Disable and remove all frp services
    enabled_servers=$(systemctl list-unit-files | grep "frps@" | awk '{print $1}' || true)
    for service in $enabled_servers; do
        systemctl disable "$service" 2>/dev/null || true
    done

    enabled_clients=$(systemctl list-unit-files | grep "frpc@" | awk '{print $1}' || true)
    for service in $enabled_clients; do
        systemctl disable "$service" 2>/dev/null || true
    done

    # Optional: tear down GRE tunnels before /root/frp is deleted
    read -p "Also remove GRE tunnel manager (tears down all tunnels)? (yes/no): " rm_gre
    if [[ "$rm_gre" == "yes" ]]; then
        local env
        for env in "$GRE_DIR"/*.env; do
            if [[ ! -e "$env" ]]; then break; fi
            IFACE=""
            # shellcheck disable=SC1090
            source "$env"
            if [[ -n "$IFACE" ]]; then
                systemctl disable --now "gre-tunnel@$IFACE" 2>/dev/null || true
                /usr/local/bin/frp-gre down "$IFACE" 2>/dev/null || true
            fi
        done
        rm -f /usr/local/bin/frp-gre /etc/systemd/system/gre-tunnel@.service
    fi

    print_info "Removing service files..."
    rm -f /etc/systemd/system/frps@.service
    rm -f /etc/systemd/system/frpc@.service

    print_info "Removing binaries..."
    rm -f /usr/local/bin/frpc
    rm -f /usr/local/bin/frps

    print_info "Removing configuration directories..."
    rm -rf /root/frp/

    # Optional: Turbo / watchdog / panel removal
    read -p "Also remove Turbo (tuning service + ZRAM)? (yes/no): " rm_turbo
    if [[ "$rm_turbo" == "yes" ]]; then
        systemctl disable --now tunnel-turbo frp-zram 2>/dev/null || true
        rm -f /usr/local/bin/frp-turbo /etc/systemd/system/tunnel-turbo.service /etc/systemd/system/frp-zram.service
        rm -f /etc/sysctl.d/99-tunnel-turbo.conf /etc/sysctl.d/99-frp-zram.conf
        crontab -l 2>/dev/null | grep -vF "pkill -10 -x frpc; pkill -10 -x frps" | crontab - 2>/dev/null || true
    fi

    read -p "Also remove Watchdog? (yes/no): " rm_wd
    if [[ "$rm_wd" == "yes" ]]; then
        systemctl disable --now frp-watchdog 2>/dev/null || true
        rm -f /usr/local/bin/frp-watchdog /etc/systemd/system/frp-watchdog.service
    fi

    read -p "Also remove the Web Panel? (yes/no): " rm_panel
    if [[ "$rm_panel" == "yes" ]]; then
        systemctl disable --now frp-panel 2>/dev/null || true
        rm -f /usr/local/bin/frp-panel /etc/systemd/system/frp-panel.service
        read -p "Also delete panel config /etc/frp-panel? (yes/no): " rm_pcfg
        if [[ "$rm_pcfg" == "yes" ]]; then
            rm -rf /etc/frp-panel
        fi
    fi

    print_info "Reloading systemd..."
    systemctl daemon-reload

    print_success "FRP completely removed from system."
}

# --- Show status (v1 + GRE / turbo / zram / watchdog / panel) ------------------
show_status() {
    print_info "FRP Service Status"
    echo

    # Check if binaries exist
    if [[ ! -f "/usr/local/bin/frpc" ]] || [[ ! -f "/usr/local/bin/frps" ]]; then
        print_warning "FRP is not installed."
    else
        print_info "Installed FRP version:"
        /usr/local/bin/frps --version 2>/dev/null || echo "Unable to determine version"
        echo
    fi

    print_info "Running services:"
    systemctl list-units --type=service --state=running | grep -E "frp[sc]@|frp-panel|frp-watchdog|gre-tunnel|tunnel-turbo|frp-zram" || echo "No FRP services running"
    echo

    print_info "Enabled services:"
    systemctl list-unit-files | grep -E "frp[sc]@.*enabled" || echo "No FRP services enabled"
    echo

    print_info "Configuration files:"
    echo "Server configs:"
    ls -la /root/frp/server/ 2>/dev/null || echo "  No server configs found"
    echo "Client configs:"
    ls -la /root/frp/client/ 2>/dev/null || echo "  No client configs found"
    echo

    # NEW: GRE tunnels
    print_info "GRE tunnels:"
    local env any_gre=0
    for env in "$GRE_DIR"/*.env; do
        if [[ ! -e "$env" ]]; then
            [[ "$any_gre" == "0" ]] && echo "  No GRE tunnels configured."
            break
        fi
        any_gre=1
        IFACE=""
        # shellcheck disable=SC1090
        source "$env"
        if [[ -n "$IFACE" ]]; then
            if /usr/local/bin/frp-gre status "$IFACE" 2>/dev/null; then
                :
            else
                echo "  $IFACE: DOWN (interface missing)"
            fi
        fi
    done
    echo

    # NEW: turbo + zram
    print_info "Turbo:"
    if systemctl is-active --quiet tunnel-turbo 2>/dev/null; then
        echo -e "  ${GREEN}tunnel-turbo.service: active${NC}"
    else
        echo -e "  ${YELLOW}tunnel-turbo.service: inactive (menu 7 to apply)${NC}"
    fi
    /usr/local/bin/frp-turbo status 2>/dev/null || echo "  frp-turbo helper not installed"
    /usr/local/bin/frp-turbo zram-status 2>/dev/null || true
    echo

    # NEW: watchdog
    print_info "Watchdog:"
    if systemctl is-active --quiet frp-watchdog 2>/dev/null; then
        echo -e "  ${GREEN}frp-watchdog.service: active${NC}"
    else
        echo -e "  ${YELLOW}frp-watchdog.service: inactive${NC}"
    fi
    echo

    # NEW: web panel
    print_info "Web Panel:"
    if systemctl is-active --quiet frp-panel 2>/dev/null; then
        echo -e "  ${GREEN}frp-panel.service: active${NC}"
        panel_info
    else
        echo -e "  ${YELLOW}frp-panel.service: not running (menu 11 to install)${NC}"
    fi
}

# --- GRE Tunnel Manager ---------------------------------------------------------

gre_menu() {
    while true; do
        clear
        print_header
        echo "GRE Reverse Tunnel Manager"
        echo "---------------------------"
        echo
        echo "1) List tunnels (status + health)"
        echo "2) Create tunnel"
        echo "3) Delete tunnel"
        echo "4) Print mirror config for the remote node"
        echo "5) Run health check now"
        echo "6) Back to Main Menu"
        echo

        read -p "Choose an option [1-6]: " gre_choice
        echo

        case $gre_choice in
            1) gre_list; pause ;;
            2) gre_create_prompt; pause ;;
            3) gre_delete_prompt; pause ;;
            4)
                read -p "Tunnel name [gt11]: " tname
                gre_mirror_print "${tname:-gt11}"
                pause
                ;;
            5) health_check; pause ;;
            6) return ;;
            *) print_error "Invalid option. Please choose 1-6."; pause ;;
        esac
    done
}

gre_list() {
    local env found=0
    for env in "$GRE_DIR"/*.env; do
        if [[ ! -e "$env" ]]; then
            if [[ "$found" == "0" ]]; then
                print_warning "No GRE tunnels configured (create one from the menu)."
            fi
            break
        fi
        found=1
        echo "==> $(basename "$env")"
        cat "$env"
        IFACE=""
        # shellcheck disable=SC1090
        source "$env"
        if [[ -n "$IFACE" ]]; then
            if /usr/local/bin/frp-gre status "$IFACE" 2>/dev/null; then
                peer="${REMOTE_PRIVATE_IP%%/*}"
                if ping -c3 -W2 -I "$IFACE" "$peer" >/dev/null 2>&1; then
                    avg=$(ping -c3 -W2 -I "$IFACE" "$peer" 2>/dev/null | awk -F'/' '/=/{print $5; exit}')
                    print_success "peer $peer reachable via $IFACE (avg ${avg} ms)"
                else
                    print_warning "peer $peer NOT reachable via $IFACE (remote side configured?)"
                fi
            else
                print_warning "$IFACE is DOWN"
            fi
        fi
        echo
    done
}

# gre_live_healthy IFACE LP RP LPRIV — true when the interface is up with the
# expected public endpoints and already carries the expected private address.
gre_live_healthy() {
    local iface="$1" lp="$2" rp="$3" lpriv="$4"
    ip link show "$iface" >/dev/null 2>&1 || return 1
    local live_iface live_lp live_rp
    while read -r live_iface live_lp live_rp; do
        [[ "$live_iface" == "$iface" ]] || continue
        if [[ "$live_lp" == "$lp" && "$live_rp" == "$rp" ]] || [[ "$live_lp" == "$rp" && "$live_rp" == "$lp" ]]; then
            ip -o -4 addr show dev "$iface" 2>/dev/null | grep -qw "${lpriv%%/*}" && return 0
        fi
    done < <(reverse_live_tunnels)
    return 1
}

# gre_env_matches IFACE LP RP LPRIV RPRIV MTU MSS TXQ — true when an existing
# env file already holds exactly these values (no requested change).
gre_env_matches() {
    local f="$GRE_DIR/$1.env"
    [[ -r "$f" ]] || return 1
    [[ "$(sed -n 's/^LOCAL_PUBLIC_IP=//p' "$f" | head -n1)" == "$2" ]] || return 1
    [[ "$(sed -n 's/^REMOTE_PUBLIC_IP=//p' "$f" | head -n1)" == "$3" ]] || return 1
    [[ "$(sed -n 's/^LOCAL_PRIVATE_IP=//p' "$f" | head -n1)" == "$4" ]] || return 1
    [[ "$(sed -n 's/^REMOTE_PRIVATE_IP=//p' "$f" | head -n1)" == "$5" ]] || return 1
    [[ "$(sed -n 's/^MTU=//p' "$f" | head -n1)" == "$6" ]] || return 1
    [[ "$(sed -n 's/^MSS_MODE=//p' "$f" | head -n1)" == "$7" ]] || return 1
    [[ "$(sed -n 's/^TXQUEUELEN=//p' "$f" | head -n1)" == "${8:-1000}" ]] || return 1
    return 0
}

# gre_create_do LP RP IFACE LPRIV RPRIV MTU MSS [TXQUEUELEN] — shared by menu + CLI
gre_create_do() {
    local lp="$1" rp="$2" iface="$3" lpriv="$4" rpriv="$5" mtu="$6" mss="$7" txq="${8:-1000}"

    if ! is_ipv4 "$lp"; then print_error "Invalid local public IP: $lp"; return 1; fi
    if ! is_ipv4 "$rp"; then print_error "Invalid remote public IP: $rp"; return 1; fi
    if ! is_cidr4 "$lpriv"; then print_error "Invalid local private CIDR: $lpriv"; return 1; fi
    if ! is_cidr4 "$rpriv"; then print_error "Invalid remote private CIDR: $rpriv"; return 1; fi
    if [[ "$lp" == "$rp" ]]; then print_error "Local and remote public IPs must differ."; return 1; fi
    if [[ "$lpriv" == "$rpriv" ]]; then print_error "Local and remote private IPs must differ."; return 1; fi
    if ! [[ "$iface" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]; then print_error "Invalid interface name: $iface"; return 1; fi
    if ! [[ "$mtu" =~ ^[0-9]+$ ]] || (( mtu < 576 || mtu > 1500 )); then
        print_error "Invalid MTU: $mtu"; return 1
    fi
    if ! [[ "$txq" =~ ^[0-9]+$ ]] || (( txq < 1 || txq > 100000 )); then
        print_error "Invalid TXQUEUELEN: $txq"; return 1
    fi
    case "$mss" in
        clamp|1360|1240|1220|off) ;;
        *) print_error "Invalid MSS mode: $mss (want clamp|1360|1240|1220|off)"; return 1 ;;
    esac

    # Warn (don't block) when the two /30s don't pair up
    local lnet rnet
    lnet="${lpriv%/*}"; rnet="${rpriv%/*}"
    if [[ "${lnet%.*}" != "${rnet%.*}" ]]; then
        print_warning "Private IPs are not in the same /24 — unusual for a p2p GRE link."
    fi

    ensure_gre_assets

    # Strictly non-destructive: if this exact tunnel is already up and healthy
    # with an unchanged definition, leave the interface and unit alone. Only a
    # request that actually changes the definition (or a missing/down tunnel)
    # proceeds to write + start/restart.
    local reuse_live=0
    if gre_live_healthy "$iface" "$lp" "$rp" "$lpriv"; then
        if [[ ! -f "$GRE_DIR/$iface.env" ]] || \
           gre_env_matches "$iface" "$lp" "$rp" "$lpriv" "$rpriv" "$mtu" "$mss" "$txq"; then
            reuse_live=1
        fi
    fi

    mkdir -p "$GRE_DIR"
    if [[ -f "$GRE_DIR/$iface.env" ]]; then
        if [[ $reuse_live -eq 0 ]]; then
            print_warning "Overwriting existing $GRE_DIR/$iface.env"
        fi
        if [[ $reuse_live -eq 0 ]]; then
            cp -a "$GRE_DIR/$iface.env" "$GRE_DIR/$iface.env.bak-$(date +%Y%m%d-%H%M%S)"
        fi
    fi
    {
        echo "# GRE tunnel definition (FRP Tunnel Suite) — managed by frp-manager / frp-panel"
        echo "LOCAL_PUBLIC_IP=$lp"
        echo "REMOTE_PUBLIC_IP=$rp"
        echo "IFACE=$iface"
        echo "LOCAL_PRIVATE_IP=$lpriv"
        echo "REMOTE_PRIVATE_IP=$rpriv"
        echo "MTU=$mtu"
        echo "MSS_MODE=$mss"
        echo "TXQUEUELEN=$txq"
    } > "$GRE_DIR/$iface.env"
    chmod 600 "$GRE_DIR/$iface.env"

    if [[ $reuse_live -eq 1 ]]; then
        # Persist boot-time management without touching the live link.
        systemctl enable "gre-tunnel@$iface" >/dev/null 2>&1 || true
        print_success "GRE tunnel $iface is already up with these endpoints — reused untouched (no restart)."
        local busy_peer="${rpriv%%/*}"
        if ping -c3 -W2 -I "$iface" "$busy_peer" >/dev/null 2>&1; then
            print_success "Tunnel $iface is up and the peer $busy_peer answers."
        fi
        return 0
    fi

    print_info "Enabling gre-tunnel@$iface..."
    systemctl enable --now "gre-tunnel@$iface"
    sleep 1
    /usr/local/bin/frp-gre status "$iface" 2>/dev/null || true

    local peer="${rpriv%%/*}"
    if ping -c3 -W2 -I "$iface" "$peer" >/dev/null 2>&1; then
        print_success "Tunnel $iface is up and the peer $peer answers."
    else
        print_warning "Peer $peer is not answering yet — the remote node is probably not configured."
        echo
        print_info "Run this on the REMOTE node:"
        gre_mirror_print "$iface"
    fi
    print_success "GRE tunnel $iface created."
}

gre_create_prompt() {
    print_info "GRE Tunnel Creation"
    local def_pub lp rp iface lpriv rpriv mtu mss txq
    def_pub=$(detect_public_ip)
    read -p "Local public IP${def_pub:+ [$def_pub]}: " lp
    lp=${lp:-$def_pub}
    read -p "Remote public IP: " rp
    read -p "Tunnel interface name [gt11]: " iface
    iface=${iface:-gt11}
    read -p "Local private IP [10.100.111.1/30]: " lpriv
    lpriv=${lpriv:-"10.100.111.1/30"}
    read -p "Remote private IP [10.100.111.2/30]: " rpriv
    rpriv=${rpriv:-"10.100.111.2/30"}
    read -p "MTU [1320]: " mtu
    mtu=${mtu:-1320}
    read -p "TX queue length (txqueuelen) [1000]: " txq
    txq=${txq:-1000}
    echo "TCP MSS clamping mode:"
    echo "  1) clamp  (auto, recommended)"
    echo "  2) 1360    (explicit)"
    echo "  3) 1240"
    echo "  4) 1220    (paranoid, for heavily filtered paths)"
    echo "  5) off"
    read -p "Choice [1]: " mss_choice
    case "$mss_choice" in
        2) mss="1360" ;; 3) mss="1240" ;; 4) mss="1220" ;; 5) mss="off" ;; 1|"") mss="clamp" ;;
        *) mss="clamp" ;;
    esac
    gre_create_do "$lp" "$rp" "$iface" "$lpriv" "$rpriv" "$mtu" "$mss" "$txq"
}

gre_delete_do() {
    local name="$1"
    if ! [[ "$name" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]; then
        print_error "Invalid tunnel name."
        return 1
    fi
    if [[ ! -f "$GRE_DIR/$name.env" ]]; then
        print_error "No tunnel named '$name' ($GRE_DIR/$name.env missing)."
        return 1
    fi
    systemctl disable --now "gre-tunnel@$name" 2>/dev/null || true
    /usr/local/bin/frp-gre down "$name" 2>/dev/null || true
    rm -f "$GRE_DIR/$name.env"
    print_success "GRE tunnel $name removed (interface, rules and env deleted)."
}

gre_delete_prompt() {
    local env
    echo "Configured tunnels:"
    for env in "$GRE_DIR"/*.env; do
        if [[ ! -e "$env" ]]; then
            print_warning "No GRE tunnels configured."
            return 0
        fi
        echo "  $(basename "$env" .env)"
    done
    read -p "Tunnel name to delete: " tname
    gre_delete_do "${tname:-}"
}

gre_mirror_print() {
    local name="$1"
    if [[ ! -f "$GRE_DIR/$name.env" ]]; then
        print_error "No tunnel named '$name' ($GRE_DIR/$name.env missing)."
        return 1
    fi
    LOCAL_PUBLIC_IP=""; REMOTE_PUBLIC_IP=""; IFACE=""; LOCAL_PRIVATE_IP=""; REMOTE_PRIVATE_IP=""; MTU=""; MSS_MODE="clamp"; TXQUEUELEN=""
    # shellcheck disable=SC1090
    source "$GRE_DIR/$name.env"
    cat <<EOF
# ---- mirror config for the REMOTE node ($IFACE) ----
# Either use the interactive wizard (frp-manager, menu 10) or run:
frp-manager gre create \\
  --local-public "$REMOTE_PUBLIC_IP" \\
  --remote-public "$LOCAL_PUBLIC_IP" \\
  --iface "$IFACE" \\
  --local-private "$REMOTE_PRIVATE_IP" \\
  --remote-private "$LOCAL_PRIVATE_IP" \\
  --mtu "${MTU:-1320}" \\
  --mss "${MSS_MODE:-clamp}" \\
  --txqueuelen "${TXQUEUELEN:-1000}"

# Equivalent env file ($GRE_DIR/$IFACE.env):
LOCAL_PUBLIC_IP=$REMOTE_PUBLIC_IP
REMOTE_PUBLIC_IP=$LOCAL_PUBLIC_IP
IFACE=$IFACE
LOCAL_PRIVATE_IP=$REMOTE_PRIVATE_IP
REMOTE_PRIVATE_IP=$LOCAL_PRIVATE_IP
MTU=${MTU:-1320}
MSS_MODE=${MSS_MODE:-clamp}
TXQUEUELEN=${TXQUEUELEN:-1000}
EOF
}

# --- FRP over GRE Reverse quick-setup ------------------------------------------

reverse_print_flow() {
    echo "User ──► Iran Public IP:<port> ──► frps (Iran) ──► GRE gtNN ──► frpc (Foreign) ──► Foreign 127.0.0.1:<port>"
}

reverse_payload_print() { # LP RP IFACE LPRIV RPRIV MTU MSS SERVERADDR PORT PROTO TOKEN [TXQUEUELEN]
    cat <<EOF
# FRP Tunnel Suite — FRP over GRE Reverse mirror (paste on the FOREIGN / exit node)
# Flow: User -> Iran Public IP:<port> -> frps (Iran) -> GRE gt11 -> frpc (Foreign) -> 127.0.0.1:<port>
IFACE=$3
LOCAL_PUBLIC_IP=$1
REMOTE_PUBLIC_IP=$2
LOCAL_PRIVATE_IP=$4
REMOTE_PRIVATE_IP=$5
MTU=$6
MSS_MODE=$7
TXQUEUELEN=${12:-1000}
SERVER_ADDR=$8
CONTROL_PORT=$9
PROTOCOL=${10}
TOKEN=${11}
EOF
}

reverse_cmd_print() { # LP RP IFACE LPRIV RPRIV MTU MSS SERVERADDR PORT PROTO TOKEN [TXQUEUELEN]
    cat <<EOF
frp-manager reverse foreign \\
  --local-public "$1" \\
  --remote-public "$2" \\
  --iface "$3" \\
  --local-private "$4" \\
  --remote-private "$5" \\
  --mtu "$6" \\
  --mss "$7" \\
  --txqueuelen "${12:-1000}" \\
  --server-addr "$8" \\
  --control-port "$9" \\
  --protocol "${10}" \\
  --token "${11}" \\
  --ports 8443,2053,443
EOF
}

reverse_parse_payload() { # file-or-stdin; sets RP_* globals
    local src="$1" line key val
    RP_IFACE=""; RP_LOCAL_PUBLIC_IP=""; RP_REMOTE_PUBLIC_IP=""; RP_LOCAL_PRIVATE_IP=""
    RP_REMOTE_PRIVATE_IP=""; RP_MTU=""; RP_MSS_MODE=""; RP_TXQUEUELEN=""; RP_SERVER_ADDR=""
    RP_CONTROL_PORT=""; RP_PROTOCOL=""; RP_TOKEN=""
    [[ "$src" == "-" ]] && src="/dev/stdin"
    if [[ ! -r "$src" ]]; then
        print_error "cannot read mirror payload: $src"
        return 1
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line//[[:space:]]/}" ]] && continue
        key="${line%%=*}"; val="${line#*=}"
        key="${key//[[:space:]]/}"
        val="${val#"${val%%[![:space:]]*}"}"
        val="${val%"${val##*[![:space:]]}"}"
        case "$key" in
            IFACE) RP_IFACE="$val" ;;
            LOCAL_PUBLIC_IP) RP_LOCAL_PUBLIC_IP="$val" ;;
            REMOTE_PUBLIC_IP) RP_REMOTE_PUBLIC_IP="$val" ;;
            LOCAL_PRIVATE_IP) RP_LOCAL_PRIVATE_IP="$val" ;;
            REMOTE_PRIVATE_IP) RP_REMOTE_PRIVATE_IP="$val" ;;
            MTU) RP_MTU="$val" ;;
            MSS_MODE) RP_MSS_MODE="$val" ;;
            TXQUEUELEN) RP_TXQUEUELEN="$val" ;;
            SERVER_ADDR) RP_SERVER_ADDR="$val" ;;
            CONTROL_PORT) RP_CONTROL_PORT="$val" ;;
            PROTOCOL) RP_PROTOCOL="$val" ;;
            TOKEN) RP_TOKEN="$val" ;;
        esac
    done < "$src"
    if [[ -z "$RP_LOCAL_PUBLIC_IP" || -z "$RP_REMOTE_PUBLIC_IP" ]]; then
        print_error "invalid payload: LOCAL_PUBLIC_IP / REMOTE_PUBLIC_IP missing."
        return 1
    fi
    return 0
}

# --- multi-tunnel allocation (GRE iface / /30 / control port) -----------------

reverse_iface_busy() { # reverse_iface_busy <iface>
    local want="$1" f
    [[ -n "$want" ]] || return 0
    if ip link show "$want" >/dev/null 2>&1; then return 0; fi
    [[ -f "$GRE_DIR/$want.env" ]] && return 0
    for f in "$GRE_DIR"/*.env; do
        [[ -e "$f" ]] || continue
        grep -qE "^IFACE=${want}$" "$f" 2>/dev/null && return 0
    done
    return 1
}

reverse_live_tunnels() { # -> "iface local_pub remote_pub" per live GRE tunnel
    command -v ip >/dev/null 2>&1 || return 0
    local line iface local_ip remote_ip i
    local -a toks
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*([^:[:space:]]+):[[:space:]]+gre([[:space:]]|/) ]] || continue
        iface="${BASH_REMATCH[1]}"
        local_ip=""; remote_ip=""
        read -r -a toks <<< "${line#*:}"
        for ((i = 0; i < ${#toks[@]}; i++)); do
            case "${toks[i]}" in
                local)  local_ip="${toks[i+1]:-}" ;;
                remote) remote_ip="${toks[i+1]:-}" ;;
            esac
        done
        [[ -n "$iface" && -n "$local_ip" && -n "$remote_ip" ]] && \
            printf '%s %s %s\n' "$iface" "$local_ip" "$remote_ip"
    done < <(ip -d tunnel show 2>/dev/null || true)
}

reverse_iface_private() { # <iface> -> "local_cidr remote_cidr"
    local iface="$1" f="$GRE_DIR/$1.env" l r
    [[ -n "$iface" ]] || return 1
    if [[ -r "$f" ]]; then
        l=$(sed -n 's/^LOCAL_PRIVATE_IP=//p' "$f" | head -n1)
        r=$(sed -n 's/^REMOTE_PRIVATE_IP=//p' "$f" | head -n1)
        if [[ -n "$l" && -n "$r" ]]; then
            printf '%s %s\n' "$l" "$r"
            return 0
        fi
    fi
    l="$(ip -o -4 addr show dev "$iface" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="inet"){print $(i+1); exit}}')"
    [[ -n "$l" ]] || return 1
    r="$(awk -F'[./]' '{
        if ($4 == 1) printf "%s.%s.%s.2/30\n", $1, $2, $3;
        else if ($4 == 2) printf "%s.%s.%s.1/30\n", $1, $2, $3;
    }' <<< "$l")"
    [[ -n "$r" ]] || return 1
    printf '%s %s\n' "$l" "$r"
}

reverse_iface_octet() { # <iface> -> third octet of its /30
    local lp rp
    read -r lp rp < <(reverse_iface_private "$1") || return 1
    [[ -n "$lp" ]] || return 1
    awk -F. '{print $3}' <<< "$lp"
}

reverse_iface_own() { # reverse_iface_own <iface> <local_pub> <remote_pub> (exact pair)
    local iface="$1" lp="$2" rp="$3" f="$GRE_DIR/$1.env" l r live_iface live_lp live_rp
    [[ -n "$iface" && -n "$lp" && -n "$rp" ]] || return 1
    if [[ -r "$f" ]]; then
        l=$(sed -n 's/^LOCAL_PUBLIC_IP=//p' "$f" | head -n1)
        r=$(sed -n 's/^REMOTE_PUBLIC_IP=//p' "$f" | head -n1)
        if [[ "$l" == "$lp" && "$r" == "$rp" ]] || [[ "$l" == "$rp" && "$r" == "$lp" ]]; then
            return 0
        fi
    fi
    while read -r live_iface live_lp live_rp; do
        [[ "$live_iface" == "$iface" ]] || continue
        if [[ "$live_lp" == "$lp" && "$live_rp" == "$rp" ]] || [[ "$live_lp" == "$rp" && "$live_rp" == "$lp" ]]; then
            return 0
        fi
    done < <(reverse_live_tunnels)
    return 1
}

reverse_iface_reusable() { # reverse_iface_reusable <iface> <remote_pub> (same remote endpoint)
    local iface="$1" rp="$2" f="$GRE_DIR/$1.env" r live_iface live_lp live_rp
    [[ -n "$iface" && -n "$rp" ]] || return 1
    if [[ -r "$f" ]]; then
        r=$(sed -n 's/^REMOTE_PUBLIC_IP=//p' "$f" | head -n1)
        [[ "$r" == "$rp" ]] && return 0
    fi
    while read -r live_iface live_lp live_rp; do
        [[ "$live_iface" == "$iface" && "$live_rp" == "$rp" ]] && return 0
    done < <(reverse_live_tunnels)
    return 1
}

reverse_find_reusable_iface() { # reverse_find_reusable_iface <local_pub> <remote_pub> -> iface
    local lp="$1" rp="$2" f base l r iface live_lp live_rp
    [[ -n "$lp" && -n "$rp" ]] || return 1
    # 1) exact pair in an env file (either orientation)
    for f in "$GRE_DIR"/*.env; do
        [[ -e "$f" ]] || continue
        l=$(sed -n 's/^LOCAL_PUBLIC_IP=//p' "$f" | head -n1)
        r=$(sed -n 's/^REMOTE_PUBLIC_IP=//p' "$f" | head -n1)
        if [[ "$l" == "$lp" && "$r" == "$rp" ]] || [[ "$l" == "$rp" && "$r" == "$lp" ]]; then
            basename "$f" .env
            return 0
        fi
    done
    # 2) live kernel tunnel with the exact pair (either orientation)
    while read -r iface live_lp live_rp; do
        [[ -n "$iface" ]] || continue
        if [[ "$live_lp" == "$lp" && "$live_rp" == "$rp" ]] || [[ "$live_lp" == "$rp" && "$live_rp" == "$lp" ]]; then
            echo "$iface"
            return 0
        fi
    done < <(reverse_live_tunnels)
    # 3) same remote endpoint (the local public IP changed)
    while read -r iface live_lp live_rp; do
        [[ -n "$iface" ]] || continue
        [[ "$live_rp" == "$rp" ]] && { echo "$iface"; return 0; }
    done < <(reverse_live_tunnels)
    for f in "$GRE_DIR"/*.env; do
        [[ -e "$f" ]] || continue
        r=$(sed -n 's/^REMOTE_PUBLIC_IP=//p' "$f" | head -n1)
        [[ "$r" == "$rp" ]] && { basename "$f" .env; return 0; }
    done
    return 1
}

reverse_octet_busy() { # reverse_octet_busy <third-octet>
    local octet="$1" f
    [[ -n "$octet" ]] || return 0
    for f in "$GRE_DIR"/*.env; do
        [[ -e "$f" ]] || continue
        grep -qE "^[A-Z_]+_PRIVATE_IP=10\.100\.${octet}\." "$f" 2>/dev/null && return 0
    done
    return 1
}

reverse_next_iface() {
    local n=11
    while (( n < 1000 )) && reverse_iface_busy "gt$n"; do
        n=$((n + 1))
    done
    echo "gt$n"
}

reverse_next_octet() {
    local n=111 first=111
    while reverse_octet_busy "$n"; do
        n=$((n + 1))
        if (( n > 254 )); then n=1; fi
        if (( n == first )); then break; fi
    done
    echo "$n"
}

reverse_alloc_gre() { # req_iface req_octet [own_local_pub own_remote_pub] -> "iface octet warning"
    local req_iface="$1" req_octet="$2" own_lp="${3:-}" own_rp="${4:-}"
    local iface octet msg="" own_iface=0 own_oct=0
    if [[ -n "$own_lp" ]] && reverse_iface_own "$req_iface" "$own_lp" "$own_rp"; then
        own_iface=1
        if [[ "$(reverse_iface_octet "$req_iface" 2>/dev/null || true)" == "$req_octet" ]]; then
            own_oct=1
        fi
    fi
    if [[ $own_iface -eq 0 ]] && reverse_iface_busy "$req_iface"; then
        msg="$req_iface was busy"; iface=""
    else
        iface="$req_iface"
    fi
    if [[ $own_oct -eq 0 ]] && reverse_octet_busy "$req_octet"; then
        [[ -n "$msg" ]] || msg="10.100.$req_octet.0/30 was in use"
        octet=""
    else
        octet="$req_octet"
    fi
    [[ -z "$iface" ]] && iface="$(reverse_next_iface)"
    [[ -z "$octet" ]] && octet="$(reverse_next_octet)"
    [[ -n "$msg" ]] && msg="$msg; allocated $iface (10.100.$octet.0/30)"
    printf '%s %s %s\n' "$iface" "$octet" "$msg"
}

reverse_own_port() { # reverse_own_port <octet> -> existing port for 10.100.<octet>.2
    local octet="$1" f bp
    for f in "$SERVER_DIR"/*.toml; do
        [[ -e "$f" ]] || continue
        grep -qE "^bindAddr *= *\"?10\.100\.${octet}\.2\"?$" "$f" 2>/dev/null || continue
        bp=$(sed -n 's/^bindPort *= *\([0-9][0-9]*\)$/\1/p' "$f" | head -n1)
        if [[ -n "$bp" ]]; then
            echo "$bp"
            return 0
        fi
    done
    return 1
}

reverse_alloc_port() { # requested_port -> "port warning"
    local req="$1" p
    [[ "$req" =~ ^[0-9]+$ ]] || req=7025
    p="$req"
    while reverse_port_busy "$p"; do
        p=$((p + 1))
        if (( p > 65535 )); then p=7025; fi
        if (( p == req )); then break; fi
    done
    if (( p != req )); then
        printf '%s %s\n' "$p" "port $req was in use; switched to $p"
    else
        printf '%s %s\n' "$p" ""
    fi
}

reverse_port_busy() { # reverse_port_busy <port>
    local p="$1" f
    [[ "$p" =~ ^[0-9]+$ ]] || return 0
    for f in "$SERVER_DIR"/*.toml; do
        [[ -e "$f" ]] || continue
        grep -qE "^bindPort *= *${p}$" "$f" 2>/dev/null && return 0
        [[ "$(basename "$f" .toml)" == "server-$p" ]] && return 0
    done
    if command -v ss >/dev/null 2>&1; then
        ss -ltn "sport = :$p" 2>/dev/null | grep -q LISTEN && return 0
    fi
    return 1
}

# reverse_iran_do IRAN_PUBLIC FOREIGN_PUBLIC [IFACE] [PORT] [PROTO] [MSS] [TXQUEUELEN]
reverse_iran_do() {
    local iran="$1" foreign="$2" iface="${3:-gt11}" port="${4:-7025}" proto="${5:-tcp}" mss="${6:-1220}" txq="${7:-1000}"
    if [[ ! -x /usr/local/bin/frps ]]; then
        print_error "frps is not installed — run menu 1 (Install FRP) first."
        return 1
    fi
    if ! is_ipv4 "$iran"; then print_error "Invalid Iran public IP: $iran"; return 1; fi
    if ! is_ipv4 "$foreign"; then print_error "Invalid Foreign public IP: $foreign"; return 1; fi
    if ! [[ "$iface" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]; then print_error "Invalid interface name: $iface"; return 1; fi
    if ! is_valid_port "$port"; then print_error "Invalid control port: $port"; return 1; fi
    case "$proto" in
        tcp|quic|kcp) ;;
        *) print_error "Invalid protocol: $proto (want tcp|quic|kcp)"; return 1 ;;
    esac
    case "$mss" in
        clamp|1360|1240|1220|off) ;;
        *) print_error "Invalid MSS mode: $mss"; return 1 ;;
    esac

    local req_octet=111 own_octet="" alloc_warn req_port own_port own_iface reused=0
    if own_iface="$(reverse_find_reusable_iface "$iran" "$foreign")"; then
        iface="$own_iface"
    fi
    if reverse_iface_own "$iface" "$iran" "$foreign"; then
        # Exact pair: a rerun refreshes this tunnel silently.
        if ! own_octet="$(reverse_iface_octet "$iface")"; then
            print_error "existing GRE tunnel $iface for $foreign has no IPv4 /30 — delete it or assign one first."
            return 1
        fi
        req_octet="$own_octet"
    elif reverse_iface_reusable "$iface" "$foreign"; then
        # Same Foreign endpoint, local public IP changed: reuse the live
        # interface and its /30 instead of adding a duplicate keyless GRE.
        if own_octet="$(reverse_iface_octet "$iface")"; then
            req_octet="$own_octet"
            reused=1
            print_warning "reused existing GRE tunnel $iface for $foreign (10.100.$req_octet.0/30)"
        else
            print_error "existing GRE tunnel $iface for $foreign has no IPv4 /30 — delete it or assign one first."
            return 1
        fi
    fi
    if [[ $reused -eq 0 ]]; then
        read -r iface req_octet alloc_warn <<< "$(reverse_alloc_gre "$iface" "$req_octet" "$iran" "$foreign")"
        [[ -n "$alloc_warn" ]] && print_warning "$alloc_warn"
    fi
    req_port="$port"
    if [[ -n "$own_octet" ]] && own_port="$(reverse_own_port "$req_octet")"; then
        port="$own_port"
    else
        read -r port alloc_warn <<< "$(reverse_alloc_port "$req_port")"
        [[ -n "$alloc_warn" ]] && print_warning "$alloc_warn"
    fi

    print_info "Creating GRE $iface: Iran $iran (10.100.$req_octet.2/30) ↔ Foreign $foreign (10.100.$req_octet.1/30)"
    gre_create_do "$iran" "$foreign" "$iface" "10.100.$req_octet.2/30" "10.100.$req_octet.1/30" 1320 "$mss" "$txq" || return 1

    local token cfg tmp server_addr
    server_addr="10.100.$req_octet.2"
    token=$(gen_token)
    cfg="$SERVER_DIR/server-$port.toml"
    tmp="$cfg.new"
    mkdir -p "$SERVER_DIR"
    if [[ -f "$cfg" ]]; then
        print_warning "Overwriting existing $cfg (backup kept)"
        cp -a "$cfg" "$cfg.bak-$(date +%Y%m%d-%H%M%S)"
    fi
    {
        echo "# Generated by frp-suite (frp-manager CLI / frp-panel Web UI)"
        echo "# FRP over GRE Reverse — Iran entry node (frps bound strictly to $iface)"
        echo "bindAddr = \"$server_addr\""
        echo "bindPort = $port"
        # Keep the control port private inside GRE while the forwarded user
        # ports listen on every interface (otherwise they are unreachable from
        # the public internet).
        echo "proxyBindAddr = \"0.0.0.0\""
        if [[ "$proto" == "quic" ]]; then
            echo "quicBindPort = $port"
        elif [[ "$proto" == "kcp" ]]; then
            echo "kcpBindPort = $port"
        fi
        echo
        if [[ "$proto" == "quic" ]]; then
            echo "transport.quic.keepalivePeriod = 10"
            echo "transport.quic.maxIdleTimeout = 30"
            echo "transport.quic.maxIncomingStreams = 100000"
        else
            echo "# transport.quic.keepalivePeriod = 10"
            echo "# transport.quic.maxIdleTimeout = 30"
            echo "# transport.quic.maxIncomingStreams = 100000"
        fi
        echo
        echo "transport.heartbeatTimeout = 90"
        echo "transport.maxPoolCount = 65535"
        echo "transport.tcpMux = false"
        echo "transport.tcpMuxKeepaliveInterval = 10"
        echo "transport.tcpKeepalive = 120"
        echo
        echo "auth.method = \"token\""
        echo "auth.token = \"$token\""
    } > "$tmp"
    chmod 600 "$tmp"
    if ! /usr/local/bin/frps verify -c "$tmp" >/dev/null 2>&1; then
        rm -f "$tmp"
        print_error "frps rejected the generated config — aborting."
        return 1
    fi
    mv "$tmp" "$cfg"

    print_info "Starting frps@server-$port (bindAddr $server_addr:$port)..."
    systemctl enable --now "frps@server-$port" || print_warning "frps@server-$port failed to start."
    sleep 1

    if [[ "${REVERSE_NO_WATCHDOG:-0}" != "1" ]]; then
        print_info "Enabling dual-layer auto-heal watchdog (15s / 3 / 60s)..."
        NONINT=1 watchdog_enable 15 3 60 || print_warning "watchdog could not be enabled."
    fi

    echo
    print_success "Iran entry node ready: frps listening only on $server_addr:$port (invisible on the public internet)."
    reverse_print_flow
    echo
    print_info "Mirror payload — paste this on the Foreign node:"
    reverse_payload_print "$foreign" "$iran" "$iface" "10.100.$req_octet.1/30" "10.100.$req_octet.2/30" 1320 "$mss" "$server_addr" "$port" "$proto" "$token" "$txq"
    echo
    print_info "Or run this on the Foreign node (add the ports it should expose):"
    reverse_cmd_print "$foreign" "$iran" "$iface" "10.100.$req_octet.1/30" "10.100.$req_octet.2/30" 1320 "$mss" "$server_addr" "$port" "$proto" "$token" "$txq"
    echo
    print_warning "Token (the Foreign frpc must use the same): $token"
}

# reverse_foreign_do LP RP IFACE LPRIV RPRIV MTU MSS SERVERADDR PORT TOKEN PORTS PROTOCOL PROTO_MODE [LOCALIP]
reverse_foreign_do() {
    local lp="$1" rp="$2" iface="$3" lpriv="$4" rpriv="$5" mtu="$6" mss="$7"
    local server_addr="$8" port="$9" token="${10}" ports="${11}" protoname="${12}"
    local proto_mode="${13:-both}" localip="${14:-127.0.0.1}" txq="${15:-1000}"
    if [[ ! -x /usr/local/bin/frpc ]]; then
        print_error "frpc is not installed — run menu 1 (Install FRP) first."
        return 1
    fi
    if ! is_ipv4 "$lp"; then print_error "Invalid Foreign public IP: $lp"; return 1; fi
    if ! is_ipv4 "$rp"; then print_error "Invalid Iran public IP: $rp"; return 1; fi
    if ! is_ipv4 "$server_addr"; then print_error "Invalid serverAddr: $server_addr"; return 1; fi
    if ! [[ "$iface" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]; then print_error "Invalid interface name: $iface"; return 1; fi
    if ! is_valid_port "$port"; then print_error "Invalid control port: $port"; return 1; fi
    if ! [[ "$token" =~ ^[A-Za-z0-9_.-]{8,128}$ ]]; then print_error "Invalid token (8..128 chars of [A-Za-z0-9_.-])."; return 1; fi
    if ! is_ipv4 "$localip"; then print_error "Invalid local IP: $localip"; return 1; fi
    case "$protoname" in
        tcp|quic|kcp) ;;
        *) print_error "Invalid protocol: $protoname (want tcp|quic|kcp)"; return 1 ;;
    esac
    case "$proto_mode" in
        both|tcp|udp) ;;
        *) print_error "Invalid proto mode: $proto_mode (want both|tcp|udp)"; return 1 ;;
    esac
    if ! expand_port_input "$ports"; then return 1; fi

    local cfg tmp p web_port web_pass alloc_warn own_iface reused=0 oct
    if own_iface="$(reverse_find_reusable_iface "$lp" "$rp")"; then
        iface="$own_iface"
    fi
    if reverse_iface_own "$iface" "$lp" "$rp" || reverse_iface_reusable "$iface" "$rp"; then
        # The same public pair, or the same Iran endpoint after the local
        # public IP changed: reuse the existing interface and its /30 instead
        # of adding a duplicate keyless GRE (`File exists`).
        if read -r lpriv rpriv < <(reverse_iface_private "$iface"); then
            # Keep the Foreign side local-first if the env is mirrored.
            local env_lp env_rp tmp_priv
            env_lp=$(sed -n 's/^LOCAL_PUBLIC_IP=//p' "$GRE_DIR/$iface.env" 2>/dev/null | head -n1)
            env_rp=$(sed -n 's/^REMOTE_PUBLIC_IP=//p' "$GRE_DIR/$iface.env" 2>/dev/null | head -n1)
            if [[ "$env_lp" == "$rp" && "$env_rp" == "$lp" ]]; then
                tmp_priv="$lpriv"; lpriv="$rpriv"; rpriv="$tmp_priv"
            fi
            if ! reverse_iface_own "$iface" "$lp" "$rp"; then
                reused=1
                oct="$(awk -F. '{print $3}' <<< "${lpriv%%/*}")"
                print_warning "reused existing GRE tunnel $iface for $rp (10.100.$oct.0/30)"
            fi
        else
            print_error "existing GRE tunnel $iface for $rp has no IPv4 /30 — delete it or assign one first."
            return 1
        fi
    fi
    if [[ $reused -eq 0 ]] && reverse_iface_busy "$iface" && ! reverse_iface_own "$iface" "$lp" "$rp"; then
        local new_iface
        new_iface="$(reverse_next_iface)"
        alloc_warn="$iface was busy locally; using $new_iface with the same mirrored /30"
        iface="$new_iface"
    fi
    [[ -n "$alloc_warn" ]] && print_warning "$alloc_warn"

    print_info "Creating GRE $iface: Foreign $lp ($lpriv) ↔ Iran $rp ($rpriv)"
    gre_create_do "$lp" "$rp" "$iface" "$lpriv" "$rpriv" "$mtu" "$mss" "$txq" || return 1
    cfg="$CLIENT_DIR/client-$port.toml"
    tmp="$cfg.new"
    web_port="$(allocate_web_port 7400 7499 "$CLIENT_DIR" 2>/dev/null || true)"
    web_pass=""
    [[ -n "$web_port" ]] && web_pass=$(gen_token)
    mkdir -p "$CLIENT_DIR"
    if [[ -f "$cfg" ]]; then
        print_warning "Overwriting existing $cfg (backup kept)"
        cp -a "$cfg" "$cfg.bak-$(date +%Y%m%d-%H%M%S)"
    fi
    {
        echo "# Generated by frp-suite (frp-manager CLI / frp-panel Web UI)"
        echo "# FRP over GRE Reverse — Foreign exit node (frpc dialing Iran over $iface)"
        echo "serverAddr = \"$server_addr\""
        echo "serverPort = $port"
        echo
        echo "loginFailExit = false"
        echo
        echo "auth.method = \"token\""
        echo "auth.token = \"$token\""
        echo
        echo "transport.protocol = \"$protoname\""
        echo "transport.tcpMux = false"
        echo "transport.tcpMuxKeepaliveInterval = 10"
        echo "transport.dialServerTimeout = 10"
        echo "transport.dialServerKeepalive = 120"
        echo "transport.poolCount = 20"
        echo "transport.heartbeatInterval = 30"
        echo "transport.heartbeatTimeout = 90"
        echo "transport.tls.enable = false"
        echo "transport.quic.keepalivePeriod = 10"
        echo "transport.quic.maxIdleTimeout = 30"
        echo "transport.quic.maxIncomingStreams = 100000"
        if [[ -n "$web_port" ]]; then
            echo
            echo "webServer.addr = \"127.0.0.1\""
            echo "webServer.port = $web_port"
            echo "webServer.user = \"admin\""
            echo "webServer.password = \"$web_pass\""
        fi
        for p in "${PORT_LIST[@]}"; do
            if [[ "$proto_mode" == "both" || "$proto_mode" == "tcp" ]]; then
                echo
                echo "[[proxies]]"
                echo "name = \"tcp-$p\""
                echo "type = \"tcp\""
                echo "localIP = \"$localip\""
                echo "localPort = $p"
                echo "remotePort = $p"
                echo "transport.useEncryption = false"
                echo "transport.useCompression = false"
            fi
            if [[ "$proto_mode" == "both" || "$proto_mode" == "udp" ]]; then
                echo
                echo "[[proxies]]"
                echo "name = \"udp-$p\""
                echo "type = \"udp\""
                echo "localIP = \"$localip\""
                echo "localPort = $p"
                echo "remotePort = $p"
                echo "transport.useEncryption = false"
                echo "transport.useCompression = false"
            fi
        done
    } > "$tmp"
    chmod 600 "$tmp"
    if ! /usr/local/bin/frpc verify -c "$tmp" >/dev/null 2>&1; then
        rm -f "$tmp"
        print_error "frpc rejected the generated config — aborting."
        return 1
    fi
    mv "$tmp" "$cfg"

    print_info "Starting frpc@client-$port (dialing $server_addr:$port over $iface)..."
    systemctl enable --now "frpc@client-$port" || print_warning "frpc@client-$port failed to start."
    sleep 1

    if [[ "${REVERSE_NO_WATCHDOG:-0}" != "1" ]]; then
        print_info "Enabling dual-layer auto-heal watchdog (15s / 3 / 60s)..."
        NONINT=1 watchdog_enable 15 3 60 || print_warning "watchdog could not be enabled."
    fi

    echo
    print_success "Foreign exit node ready: frpc@client-$port exposes ${EXPANDED_COUNT} local port(s) on the Iran entry node."
    reverse_print_flow
    echo
    print_info "Quick link test:"
    local peer avg
    peer="${rpriv%%/*}"
    if ping -c3 -W2 -I "$iface" "$peer" >/dev/null 2>&1; then
        avg=$(ping -c3 -W2 -I "$iface" "$peer" 2>/dev/null | awk -F'/' '/=/{print $5; exit}')
        print_success "GRE peer $peer reachable via $iface (avg ${avg:-?} ms)."
    else
        print_warning "GRE peer $peer is not answering yet — check protocol 47 and the Iran entry node."
    fi
    if systemctl is-active --quiet "frpc@client-$port"; then
        print_success "frpc@client-$port is active."
    else
        print_warning "frpc@client-$port is not active. Last log lines:"
        journalctl -u "frpc@client-$port" --no-pager -n 20 2>/dev/null || true
    fi
}

reverse_iran_prompt() {
    local def_pub iran foreign iface port proto_choice proto mss def_iface def_port
    def_iface="$(reverse_next_iface)"
    def_port="$(reverse_alloc_port 7025 | awk '{print $1}')"
    def_pub=$(detect_public_ip)
    read -p "Iran public IP${def_pub:+ [$def_pub]}: " iran
    iran=${iran:-$def_pub}
    read -p "Foreign public IP: " foreign
    read -p "GRE interface [$def_iface]: " iface
    iface=${iface:-$def_iface}
    read -p "Tunnel control port [$def_port]: " port
    port=${port:-$def_port}
    echo "FRP protocol:"
    echo "  1) tcp  (plain — recommended over GRE)"
    echo "  2) quic"
    echo "  3) kcp"
    read -p "Choice [1]: " proto_choice
    case "$proto_choice" in 2) proto="quic" ;; 3) proto="kcp" ;; *) proto="tcp" ;; esac
    mss="1220"
    reverse_iran_do "$iran" "$foreign" "$iface" "$port" "$proto" "$mss"
}

reverse_foreign_prompt() {
    local def_pub lp rp port token protoname proto_mode ports localip payload_choice payload_file
    local iface lpriv rpriv mtu mss server_addr txq
    echo "Do you have a mirror payload from the Iran node?"
    echo "  1) Yes — read it from a file"
    echo "  2) No — enter the values manually"
    read -p "Choice [2]: " payload_choice
    if [[ "$payload_choice" == "1" ]]; then
        read -p "Path to the payload file: " payload_file
        reverse_parse_payload "$payload_file" || return 1
        lp="$RP_LOCAL_PUBLIC_IP"; rp="$RP_REMOTE_PUBLIC_IP"
        iface="${RP_IFACE:-gt11}"; lpriv="${RP_LOCAL_PRIVATE_IP:-10.100.111.1/30}"
        rpriv="${RP_REMOTE_PRIVATE_IP:-10.100.111.2/30}"; mtu="${RP_MTU:-1320}"
        mss="${RP_MSS_MODE:-1220}"; server_addr="${RP_SERVER_ADDR:-10.100.111.2}"
        txq="${RP_TXQUEUELEN:-1000}"
        port="${RP_CONTROL_PORT:-7025}"; token="$RP_TOKEN"; protoname="${RP_PROTOCOL:-tcp}"
    else
        def_pub=$(detect_public_ip)
        read -p "Foreign public IP${def_pub:+ [$def_pub]}: " lp
        lp=${lp:-$def_pub}
        read -p "Iran public IP: " rp
        iface="$(reverse_next_iface)"; lpriv="10.100.111.1/30"; rpriv="10.100.111.2/30"
        mtu="1320"; mss="1220"; server_addr="10.100.111.2"; txq="1000"
        read -p "Tunnel control port [7025]: " port
        port=${port:-7025}
        read -p "Auth token (from the Iran node): " token
        echo "FRP protocol: 1) tcp  2) quic  3) kcp"
        read -p "Choice [1]: " proto_choice
        case "$proto_choice" in 2) protoname="quic" ;; 3) protoname="kcp" ;; *) protoname="tcp" ;; esac
    fi
    read -p "Local ports to expose (e.g. 8443,2053,443): " ports
    echo "Emit per port: 1) TCP + UDP  2) TCP only  3) UDP only"
    read -p "Choice [1]: " proto_choice
    case "$proto_choice" in 2) proto_mode="tcp" ;; 3) proto_mode="udp" ;; *) proto_mode="both" ;; esac
    read -p "Local IP on this node [127.0.0.1]: " localip
    localip=${localip:-127.0.0.1}
    reverse_foreign_do "$lp" "$rp" "$iface" "$lpriv" "$rpriv" "$mtu" "$mss" \
        "$server_addr" "$port" "$token" "$ports" "$protoname" "$proto_mode" "$localip" "$txq"
}

reverse_menu() {
    while true; do
        clear
        print_header
        echo "FRP over GRE Reverse — Quick Setup"
        echo "----------------------------------"
        echo
        reverse_print_flow
        echo
        echo "Iran is the entry bridge (frps bound to a tunnel IP); Foreign is the"
        echo "exit backend (frpc dialing it over GRE). Configure Iran first, then Foreign."
        echo "Busy gtNN interfaces, /30 subnets and control ports are allocated automatically."
        echo
        echo "1) Iran node — entry / frps"
        echo "2) Foreign node — exit / frpc"
        echo "3) Back to Main Menu"
        echo
        read -p "Choose an option [1-3]: " rev_choice
        echo
        case "$rev_choice" in
            1) reverse_iran_prompt; pause ;;
            2) reverse_foreign_prompt; pause ;;
            3) return ;;
            *) print_error "Invalid option. Please choose 1-3."; pause ;;
        esac
    done
}

reverse_cli() {
    local action="${1:-}"
    shift || true
    case "$action" in
        iran)
            local iran="" foreign="" iface="gt11" port="7025" proto="tcp" mss="1220" txq="1000"
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --iran-public) iran="$2"; shift 2 ;;
                    --foreign-public) foreign="$2"; shift 2 ;;
                    --iface) iface="$2"; shift 2 ;;
                    --port|--control-port) port="$2"; shift 2 ;;
                    --protocol) proto="$2"; shift 2 ;;
                    --mss) mss="$2"; shift 2 ;;
                    --txqueuelen) txq="$2"; shift 2 ;;
                    --no-watchdog) REVERSE_NO_WATCHDOG=1; shift ;;
                    *) print_error "unknown flag: $1"; exit 1 ;;
                esac
            done
            reverse_iran_do "$iran" "$foreign" "$iface" "$port" "$proto" "$mss" "$txq"
            ;;
        foreign)
            local payload="" lp="" rp="" iface="" lpriv="" rpriv="" mtu="" mss="" txq=""
            local server_addr="" port="" token="" ports="" protoname="" proto_mode="both" localip="127.0.0.1"
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --payload) payload="$2"; shift 2 ;;
                    --local-public) lp="$2"; shift 2 ;;
                    --remote-public) rp="$2"; shift 2 ;;
                    --iface) iface="$2"; shift 2 ;;
                    --local-private) lpriv="$2"; shift 2 ;;
                    --remote-private) rpriv="$2"; shift 2 ;;
                    --mtu) mtu="$2"; shift 2 ;;
                    --mss) mss="$2"; shift 2 ;;
                    --txqueuelen) txq="$2"; shift 2 ;;
                    --server-addr) server_addr="$2"; shift 2 ;;
                    --control-port|--port) port="$2"; shift 2 ;;
                    --token) token="$2"; shift 2 ;;
                    --ports) ports="$2"; shift 2 ;;
                    --protocol) protoname="$2"; shift 2 ;;
                    --proto) proto_mode="$2"; shift 2 ;;
                    --local-ip) localip="$2"; shift 2 ;;
                    --no-watchdog) REVERSE_NO_WATCHDOG=1; shift ;;
                    *) print_error "unknown flag: $1"; exit 1 ;;
                esac
            done
            if [[ -n "$payload" ]]; then
                reverse_parse_payload "$payload" || exit 1
                [[ -z "$lp" ]] && lp="$RP_LOCAL_PUBLIC_IP"
                [[ -z "$rp" ]] && rp="$RP_REMOTE_PUBLIC_IP"
                [[ -z "$iface" ]] && iface="${RP_IFACE:-gt11}"
                [[ -z "$lpriv" ]] && lpriv="${RP_LOCAL_PRIVATE_IP:-10.100.111.1/30}"
                [[ -z "$rpriv" ]] && rpriv="${RP_REMOTE_PRIVATE_IP:-10.100.111.2/30}"
                [[ -z "$mtu" ]] && mtu="${RP_MTU:-1320}"
                [[ -z "$mss" ]] && mss="${RP_MSS_MODE:-1220}"
                [[ -z "$txq" ]] && txq="${RP_TXQUEUELEN:-1000}"
                [[ -z "$server_addr" ]] && server_addr="${RP_SERVER_ADDR:-10.100.111.2}"
                [[ -z "$port" ]] && port="${RP_CONTROL_PORT:-7025}"
                [[ -z "$token" ]] && token="$RP_TOKEN"
                [[ -z "$protoname" ]] && protoname="${RP_PROTOCOL:-tcp}"
            fi
            [[ -z "$iface" ]] && iface="gt11"
            [[ -z "$lpriv" ]] && lpriv="10.100.111.1/30"
            [[ -z "$rpriv" ]] && rpriv="10.100.111.2/30"
            [[ -z "$mtu" ]] && mtu="1320"
            [[ -z "$mss" ]] && mss="1220"
            [[ -z "$txq" ]] && txq="1000"
            [[ -z "$server_addr" ]] && server_addr="10.100.111.2"
            [[ -z "$port" ]] && port="7025"
            [[ -z "$protoname" ]] && protoname="tcp"
            if [[ -z "$ports" ]]; then
                print_error "usage: frp-manager reverse foreign ... --ports 8443,2053,443"
                exit 1
            fi
            reverse_foreign_do "$lp" "$rp" "$iface" "$lpriv" "$rpriv" "$mtu" "$mss" \
                "$server_addr" "$port" "$token" "$ports" "$protoname" "$proto_mode" "$localip" "$txq"
            ;;
        *)
            print_error "usage: frp-manager reverse iran|foreign ..."
            exit 1
            ;;
    esac
}

# --- Web Panel manager ------------------------------------------------------------

panel_conf_value() { # panel_conf_value <key> <default>
    local key="$1" def="$2" val=""
    if [[ -r "$PANEL_CONF_DIR/panel.toml" ]]; then
        val=$(sed -nE "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*['\"]?([^'\"]*)['\"]?[[:space:]]*$/\1/p" \
            "$PANEL_CONF_DIR/panel.toml" | head -n1)
    fi
    echo "${val:-$def}"
}

panel_open_firewall() {
    local bind port
    bind="$(panel_conf_value bind "0.0.0.0")"
    port="$(panel_conf_value port "$PANEL_DEFAULT_PORT")"
    case "$bind" in
        127.0.0.1|localhost|::1|"[::1]") return 0 ;;
    esac
    if command -v ufw >/dev/null 2>&1; then
        if ufw allow "${port}/tcp" >/dev/null 2>&1; then
            print_info "UFW: allowed ${port}/tcp for the panel (bind ${bind})."
        else
            print_warning "UFW rule for ${port}/tcp could not be added; open it manually if the panel is unreachable."
        fi
    fi
}

panel_menu() {
    while true; do
        clear
        print_header
        echo "Web Panel Manager (frp-panel)"
        echo "-----------------------------"
        echo
        echo "1) Install / upgrade panel (systemd service, port $PANEL_DEFAULT_PORT)"
        echo "2) Status & access info"
        echo "3) Start"
        echo "4) Stop"
        echo "5) Restart"
        echo "6) Change port"
        echo "7) Uninstall"
        echo "8) Back to Main Menu"
        echo

        read -p "Choose an option [1-8]: " panel_choice
        echo

        case $panel_choice in
            1) panel_install ""; pause ;;
            2) panel_info; pause ;;
            3) systemctl start frp-panel && print_success "Panel started."; pause ;;
            4) systemctl stop frp-panel && print_success "Panel stopped."; pause ;;
            5) systemctl restart frp-panel && print_success "Panel restarted."; pause ;;
            6) panel_change_port_prompt; pause ;;
            7) panel_uninstall_prompt; pause ;;
            8) return ;;
            *) print_error "Invalid option. Please choose 1-8."; pause ;;
        esac
    done
}

panel_install() { # $1 = optional local tarball path (empty = download release)
    local src="${1:-}" arch
    if ! command -v curl >/dev/null 2>&1 || ! command -v tar >/dev/null 2>&1; then
        print_error "curl and tar are required."
        return 1
    fi

    case "$(uname -m)" in
        x86_64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) print_error "Unsupported arch: $(uname -m)"; return 1 ;;
    esac

    if [[ -z "$src" ]]; then
        local url
        url="${PANEL_RELEASE_BASE}/frp-panel_linux_${arch}.tar.gz"
        print_info "Downloading $url"
        if ! curl -fL "$url" -o /tmp/frp-panel.tar.gz; then
            print_error "Download failed — no release published yet, or unreachable URL."
            print_info "Set FRP_PANEL_RELEASE_BASE or pass a local tarball: panel install --file <path>"
            return 1
        fi
        src="/tmp/frp-panel.tar.gz"
    fi

    rm -rf /tmp/frp-panel-stage
    mkdir -p /tmp/frp-panel-stage
    if ! tar -xzf "$src" -C /tmp/frp-panel-stage; then
        print_error "Failed to extract $src"
        return 1
    fi
    if [[ ! -f /tmp/frp-panel-stage/frp-panel ]]; then
        print_error "Tarball does not contain ./frp-panel"
        return 1
    fi

    install -m 0755 /tmp/frp-panel-stage/frp-panel /usr/local/bin/frp-panel
    mkdir -p "$PANEL_CONF_DIR" "$PANEL_LOG_DIR"
    ensure_panel_unit
    systemctl enable --now frp-panel
    sleep 1
    panel_open_firewall

    print_success "Web Panel installed and started."
    panel_info
    print_warning "On first start the panel generates a one-time admin password; view it with:"
    echo "    journalctl -u frp-panel --no-pager | grep -i password | head -n1"
}

panel_info() {
    if ! command -v frp-panel >/dev/null 2>&1; then
        print_warning "frp-panel is not installed (menu 11, option 1)."
        return 0
    fi
    print_info "Panel service:"
    systemctl status frp-panel --no-pager -l 2>/dev/null | head -n 3 || true
    local port bind
    port="$(panel_conf_value port "$PANEL_DEFAULT_PORT")"
    bind="$(panel_conf_value bind "0.0.0.0")"
    echo
    print_info "Access URLs (bind $bind, port $port):"
    case "$bind" in
        127.0.0.1|localhost)
            echo "  http://127.0.0.1:$port"
            ;;
        ::1|"[::1]")
            echo "  http://[::1]:$port"
            ;;
        0.0.0.0|::)
            local ip
            for ip in $(ip -o -4 addr show 2>/dev/null | awk '$2 != "lo" {print $4}' | cut -d/ -f1); do
                echo "  http://$ip:$port"
            done
            ;;
        *)
            echo "  http://$bind:$port"
            ;;
    esac
}

panel_change_port_prompt() {
    if ! command -v frp-panel >/dev/null 2>&1; then
        print_error "frp-panel is not installed."
        return 1
    fi
    read -p "New port [$PANEL_DEFAULT_PORT]: " new_port
    new_port=${new_port:-$PANEL_DEFAULT_PORT}
    if ! is_valid_port "$new_port"; then
        print_error "Invalid port."
        return 1
    fi
    if [[ ! -f "$PANEL_CONF_DIR/panel.toml" ]]; then
        print_error "$PANEL_CONF_DIR/panel.toml not found — start the panel once first."
        return 1
    fi
    sed -i "s/^port *=.*/port = $new_port/" "$PANEL_CONF_DIR/panel.toml"
    systemctl restart frp-panel
    panel_open_firewall
    print_success "Panel port changed to $new_port and service restarted."
}

panel_uninstall_prompt() {
    if ! confirm_yes "Uninstall the Web Panel (configs are kept unless you delete them)?"; then
        print_info "Cancelled."
        return 0
    fi
    systemctl disable --now frp-panel 2>/dev/null || true
    rm -f /usr/local/bin/frp-panel /etc/systemd/system/frp-panel.service
    read -p "Also delete $PANEL_CONF_DIR (panel config)? (yes/no): " del_cfg
    if [[ "$del_cfg" == "yes" ]]; then
        rm -rf "$PANEL_CONF_DIR"
    fi
    systemctl daemon-reload
    print_success "Web Panel uninstalled."
}

# --- Backup / Restore ---------------------------------------------------------------

backup_menu() {
    while true; do
        clear
        print_header
        echo "Backup / Restore"
        echo "----------------"
        echo
        echo "1) Export (tar.gz: FRP + GRE configs, units, turbo, optional panel)"
        echo "2) Import (selective, existing files saved as .bak-<ts>)"
        echo "3) Back to Main Menu"
        echo

        read -p "Choose an option [1-3]: " b_choice
        echo

        case $b_choice in
            1) backup_export ""; pause ;;
            2)
                read -p "Backup file path: " bfile
                backup_import "${bfile:-}"
                pause
                ;;
            3) return ;;
            *) print_error "Invalid option."; pause ;;
        esac
    done
}

backup_export() { # $1 = optional output path
    local ts out items=() u inc
    ts=$(date +%Y%m%d-%H%M%S)
    out="${1:-/root/frp-suite-backup-$ts.tar.gz}"

    if [[ -d "$SERVER_DIR" ]]; then items+=("root/frp/server"); fi
    if [[ -d "$CLIENT_DIR" ]]; then items+=("root/frp/client"); fi
    if [[ -d "$GRE_DIR" ]]; then items+=("root/frp/gre"); fi
    for u in frps@.service frpc@.service gre-tunnel@.service tunnel-turbo.service frp-zram.service frp-watchdog.service frp-panel.service; do
        if [[ -f "/etc/systemd/system/$u" ]]; then
            items+=("etc/systemd/system/$u")
        fi
    done
    if [[ -f /etc/sysctl.d/99-tunnel-turbo.conf ]]; then items+=("etc/sysctl.d/99-tunnel-turbo.conf"); fi
    if [[ -f /etc/modules-load.d/bbr.conf ]]; then items+=("etc/modules-load.d/bbr.conf"); fi
    if [[ -d "$PANEL_CONF_DIR" ]]; then
        if [[ "${NONINT:-}" == "1" ]]; then
            print_info "NONINT mode: panel config excluded (secrets)."
        else
            read -p "Include panel config WITH secrets (admin hash, JWT secret)? (yes/no) [no]: " inc
            if [[ "$inc" == "yes" ]]; then
                items+=("etc/frp-panel")
            fi
        fi
    fi

    if [[ ${#items[@]} -eq 0 ]]; then
        print_warning "Nothing to back up."
        return 0
    fi

    print_info "Writing $out ..."
    tar -czf "$out" -C / "${items[@]}"
    print_success "Backup written: $out"
    sha256sum "$out" || true
    print_info "Contents:"
    tar -tzf "$out"
}

backup_import() { # $1 = backup file path (required)
    local path="${1:-}"
    if [[ -z "$path" ]]; then
        print_error "Backup file path required."
        return 1
    fi
    if [[ ! -f "$path" ]]; then
        print_error "File not found: $path"
        return 1
    fi

    local stage="/tmp/frp-restore-$$"
    rm -rf "$stage"
    mkdir -p "$stage"
    if ! tar -xzf "$path" -C "$stage"; then
        print_error "Not a valid tar.gz backup: $path"
        rm -rf "$stage"
        return 1
    fi

    local found=()
    if [[ -d "$stage/root/frp" ]]; then found+=("FRP+GRE configs"); fi
    if [[ -d "$stage/etc/systemd/system" ]]; then found+=("systemd units"); fi
    if [[ -d "$stage/etc/sysctl.d" || -d "$stage/etc/modules-load.d" ]]; then found+=("turbo sysctls"); fi
    if [[ -d "$stage/etc/frp-panel" ]]; then found+=("panel config"); fi

    if [[ ${#found[@]} -eq 0 ]]; then
        print_error "No recognized backup categories inside $path"
        rm -rf "$stage"
        return 1
    fi

    print_info "Found categories: ${found[*]}"
    if ! confirm_yes "Restore ALL found categories (current files become .bak-<ts>)?"; then
        print_info "Cancelled."
        rm -rf "$stage"
        return 0
    fi

    local bak_ts
    bak_ts=$(date +%Y%m%d-%H%M%S)

    if [[ -d "$stage/root/frp" ]]; then
        if [[ -d /root/frp ]]; then
            cp -a /root/frp "/root/frp.bak-$bak_ts"
        fi
        mkdir -p /root/frp
        cp -a "$stage/root/frp/." /root/frp/
        print_success "Restored /root/frp (pre-existing copy: /root/frp.bak-$bak_ts)"
    fi
    if [[ -d "$stage/etc/systemd/system" ]]; then
        local f
        find "$stage/etc/systemd/system" -maxdepth 1 -type f | while read -r f; do
            local base
            base="/etc/systemd/system/$(basename "$f")"
            if [[ -f "$base" ]]; then
                cp -a "$base" "$base.bak-$bak_ts"
            fi
            cp -a "$f" "$base"
            echo "  restored unit: $(basename "$f")"
        done
        systemctl daemon-reload
        print_success "Restored systemd units"
    fi
    if [[ -d "$stage/etc/sysctl.d" ]]; then
        cp -a "$stage/etc/sysctl.d/." /etc/sysctl.d/
        sysctl --system >/dev/null 2>&1 || true
        print_success "Restored sysctl drop-ins"
    fi
    if [[ -d "$stage/etc/modules-load.d" ]]; then
        mkdir -p /etc/modules-load.d
        cp -a "$stage/etc/modules-load.d/." /etc/modules-load.d/
        print_success "Restored modules-load config"
    fi
    if [[ -d "$stage/etc/frp-panel" ]]; then
        mkdir -p "$PANEL_CONF_DIR"
        cp -a "$stage/etc/frp-panel/." "$PANEL_CONF_DIR/"
        print_success "Restored panel config"
    fi

    read -p "Restart affected services now? (y/n) [y]: " rs
    if [[ "$rs" =~ ^[Yy]?$ ]]; then
        local unit
        for unit in $(systemctl list-units --type=service --state=running | grep -E "frp[sc]@|gre-tunnel@" | awk '{print $1}' || true); do
            print_info "Restarting $unit ..."
            systemctl restart "$unit" 2>/dev/null || true
        done
    fi

    rm -rf "$stage"
    print_success "Restore complete."
}

# --- Watchdog & Health ---------------------------------------------------------------

watchdog_menu() {
    while true; do
        clear
        print_header
        echo "Dual-Layer Watchdog & Health Monitor"
        echo "-------------------------"
        echo
        echo "1) Enable watchdog (auto-heal GRE + frpc)"
        echo "2) Disable watchdog"
        echo "3) Watchdog status"
        echo "4) Tail heal events"
        echo "5) Configure Telegram alerts"
        echo "6) Send a Telegram test alert"
        echo "7) Run health check now"
        echo "8) Back to Main Menu"
        echo

        read -p "Choose an option [1-8]: " wd_choice
        echo

        case $wd_choice in
            1) watchdog_enable 15 3 60; pause ;;
            2) watchdog_disable; pause ;;
            3) watchdog_status; pause ;;
            4) tail -n 30 "$PANEL_LOG_DIR/watchdog.log" 2>/dev/null || print_warning "No watchdog log yet."; pause ;;
            5) watchdog_telegram_setup; pause ;;
            6) watchdog_telegram_test; pause ;;
            7) health_check; pause ;;
            8) return ;;
            *) print_error "Invalid option."; pause ;;
        esac
    done
}

watchdog_enable() { # [interval] [threshold] [cooldown] [tg_token] [tg_chat] [tg_api_base]
    local interval="${1:-15}" threshold="${2:-3}" cooldown="${3:-60}"
    local tg_token="${4-__KEEP__}" tg_chat="${5-__KEEP__}" tg_api_base="${6-__KEEP__}"
    local old_token="" old_chat="" old_api="https://api.telegram.org"

    # Preserve an existing Telegram setup when the caller only retunes timings.
    if [[ -r "$PANEL_CONF_DIR/watchdog.env" ]]; then
        # shellcheck disable=SC1090
        source "$PANEL_CONF_DIR/watchdog.env"
        old_token="${TG_BOT_TOKEN:-}"
        old_chat="${TG_CHAT_ID:-}"
        old_api="${TG_API_BASE:-https://api.telegram.org}"
    fi
    [[ "$tg_token" == "__KEEP__" ]] && tg_token="$old_token"
    [[ "$tg_chat" == "__KEEP__" ]] && tg_chat="$old_chat"
    [[ "$tg_api_base" == "__KEEP__" ]] && tg_api_base="$old_api"

    if [[ "${NONINT:-}" != "1" ]]; then
        read -p "Probe interval in seconds [15]: " interval
        interval=${interval:-15}
        read -p "Failures before restart [3]: " threshold
        threshold=${threshold:-3}
        read -p "Restart cooldown in seconds [60]: " cooldown
        cooldown=${cooldown:-60}
    fi
    if ! [[ "$interval" =~ ^[0-9]+$ ]] || (( interval < 10 )); then
        print_error "Interval must be >= 10 seconds."; return 1
    fi
    if ! [[ "$threshold" =~ ^[0-9]+$ ]] || (( threshold < 1 )); then
        print_error "Threshold must be >= 1."; return 1
    fi
    if ! [[ "$cooldown" =~ ^[0-9]+$ ]]; then
        print_error "Cooldown must be numeric."; return 1
    fi
    if ! [[ "$tg_token" =~ ^[A-Za-z0-9:_-]*$ ]]; then
        print_error "Invalid Telegram bot token (allowed: A-Z a-z 0-9 : _ -)."; return 1
    fi
    if ! [[ "$tg_chat" =~ ^[-@A-Za-z0-9_]*$ ]]; then
        print_error "Invalid Telegram chat ID (allowed: A-Z a-z 0-9 _ - @)."; return 1
    fi
    tg_api_base="${tg_api_base:-https://api.telegram.org}"
    tg_api_base="${tg_api_base%/}"
    if ! [[ "$tg_api_base" =~ ^https?://[A-Za-z0-9._:/-]+$ ]]; then
        print_error "Invalid Telegram API base (want http(s)://host[/path])."; return 1
    fi
    if [[ -n "$tg_token" && -z "$tg_chat" ]] || [[ -z "$tg_token" && -n "$tg_chat" ]]; then
        print_warning "Telegram needs both a bot token and a chat ID — alerts stay disabled."
    fi

    ensure_watchdog_assets
    mkdir -p "$PANEL_CONF_DIR"
    cat > "$PANEL_CONF_DIR/watchdog.env" <<EOF
# FRP Tunnel Suite watchdog tuning (used by /usr/local/bin/frp-watchdog)
INTERVAL=$interval
THRESHOLD=$threshold
COOLDOWN=$cooldown
PING_TIMEOUT=2
TCP_TIMEOUT=3
TG_BOT_TOKEN=$tg_token
TG_CHAT_ID=$tg_chat
TG_API_BASE=$tg_api_base
EOF
    chmod 600 "$PANEL_CONF_DIR/watchdog.env"
    systemctl enable --now frp-watchdog
    systemctl restart frp-watchdog 2>/dev/null || true
    if [[ -n "$tg_token" && -n "$tg_chat" ]]; then
        print_success "Watchdog enabled (interval=${interval}s threshold=$threshold cooldown=${cooldown}s, Telegram on)."
    else
        print_success "Watchdog enabled (interval=${interval}s threshold=$threshold cooldown=${cooldown}s)."
    fi
}

watchdog_telegram_setup() {
    local interval="15" threshold="3" cooldown="60"
    local old_token="" old_chat="" old_api="https://api.telegram.org"
    if [[ -r "$PANEL_CONF_DIR/watchdog.env" ]]; then
        # shellcheck disable=SC1090
        source "$PANEL_CONF_DIR/watchdog.env"
        interval="${INTERVAL:-15}"; threshold="${THRESHOLD:-3}"; cooldown="${COOLDOWN:-60}"
        old_token="${TG_BOT_TOKEN:-}"; old_chat="${TG_CHAT_ID:-}"
        old_api="${TG_API_BASE:-https://api.telegram.org}"
    fi
    print_info "Telegram alerts (leave the token blank to keep the current one)"
    local token chat base
    read -r -p "Bot token${old_token:+ [keep current]}: " token
    read -r -p "Chat ID${old_chat:+ [$old_chat]}: " chat
    chat=${chat:-$old_chat}
    read -r -p "API base [$old_api]: " base
    base=${base:-$old_api}
    if [[ -z "$token" ]]; then
        token="__KEEP__"
    fi
    watchdog_enable "$interval" "$threshold" "$cooldown" "$token" "$chat" "$base"
}

watchdog_telegram_test() {
    local token="" chat="" base="https://api.telegram.org"
    if [[ -r "$PANEL_CONF_DIR/watchdog.env" ]]; then
        # shellcheck disable=SC1090
        source "$PANEL_CONF_DIR/watchdog.env"
        token="${TG_BOT_TOKEN:-}"; chat="${TG_CHAT_ID:-}"
        base="${TG_API_BASE:-https://api.telegram.org}"
    fi
    if [[ -z "$token" || -z "$chat" ]]; then
        print_error "Telegram is not configured (set a bot token and chat ID first)."
        return 1
    fi
    base="${base%/}"
    local host text
    host="$(hostname 2>/dev/null || echo this-server)"
    text="$(printf 'FRP Tunnel Suite test alert\nHost: %s\nStatus: Telegram connectivity OK — watchdog alerts are wired up.' "$host")"
    if curl -fsS --max-time 8 \
        --data-urlencode "chat_id=${chat}" \
        --data-urlencode "text=${text}" \
        --data-urlencode "disable_web_page_preview=true" \
        "${base}/bot${token}/sendMessage" >/dev/null 2>&1; then
        print_success "Telegram test alert sent to chat $chat."
    else
        print_error "Telegram delivery failed (check the token, chat ID and API base)."
        return 1
    fi
}

watchdog_disable() {
    systemctl disable --now frp-watchdog 2>/dev/null || true
    print_success "Watchdog disabled."
}

watchdog_status() {
    if systemctl is-active --quiet frp-watchdog 2>/dev/null; then
        print_success "frp-watchdog.service: active"
        if [[ -r "$PANEL_CONF_DIR/watchdog.env" ]]; then
            grep -E '^(INTERVAL|THRESHOLD|COOLDOWN|PING_TIMEOUT|TCP_TIMEOUT)' "$PANEL_CONF_DIR/watchdog.env" | sed 's/^/  /'
            local tg_token="" tg_chat="" tg_api=""
            # shellcheck disable=SC1090
            source "$PANEL_CONF_DIR/watchdog.env"
            tg_token="${TG_BOT_TOKEN:-}"; tg_chat="${TG_CHAT_ID:-}"
            tg_api="${TG_API_BASE:-https://api.telegram.org}"
            if [[ -n "$tg_token" && -n "$tg_chat" ]]; then
                print_info "Telegram alerts: enabled (chat $tg_chat, api $tg_api, token ••••$(printf '%s' "$tg_token" | tail -c 5))"
            else
                print_info "Telegram alerts: disabled"
            fi
        fi
    else
        print_warning "frp-watchdog.service: inactive"
    fi
    if [[ -r "$PANEL_LOG_DIR/watchdog.log" ]]; then
        echo
        print_info "Recent events:"
        tail -n 5 "$PANEL_LOG_DIR/watchdog.log" | sed 's/^/  /'
    fi
}

health_check() {
    print_info "Tunnel Health Check"
    echo "----------------------------------------"

    local env unit name cfg addr port bp cfgfile avg peer
    local found_gre=0

    for env in "$GRE_DIR"/*.env; do
        if [[ ! -e "$env" ]]; then
            break
        fi
        found_gre=1
        IFACE=""; REMOTE_PUBLIC_IP=""; REMOTE_PRIVATE_IP=""
        # shellcheck disable=SC1090
        source "$env"
        [[ -n "$IFACE" ]] || continue
        peer="${REMOTE_PRIVATE_IP%%/*}"
        if ! ip link show "$IFACE" >/dev/null 2>&1; then
            print_error "GRE $IFACE: interface missing"
        elif ping -c3 -W2 -I "$IFACE" "$peer" >/dev/null 2>&1; then
            avg=$(ping -c3 -W2 -I "$IFACE" "$peer" 2>/dev/null | awk -F'/' '/=/{print $5; exit}')
            print_success "GRE $IFACE -> $peer (via tunnel): OK  avg=${avg} ms"
        else
            print_error "GRE $IFACE -> $peer (via tunnel): FAIL (loss/timeout)"
        fi
        if ping -c3 -W2 "${REMOTE_PUBLIC_IP:-}" >/dev/null 2>&1; then
            avg=$(ping -c3 -W2 "$REMOTE_PUBLIC_IP" 2>/dev/null | awk -F'/' '/=/{print $5; exit}')
            print_info "GRE $IFACE -> $REMOTE_PUBLIC_IP (public): OK  avg=${avg} ms"
        else
            print_warning "GRE $IFACE -> ${REMOTE_PUBLIC_IP:-?} (public): no reply"
        fi
    done
    if [[ "$found_gre" == "0" ]]; then
        print_warning "No GRE tunnels configured."
    fi

    echo "----------------------------------------"
    local found_frpc=0
    for unit in $(systemctl list-unit-files 'frpc@*.service' --no-legend 2>/dev/null | awk '$2=="enabled"{print $1}'); do
        found_frpc=1
        name="${unit#frpc@}"; name="${name%.service}"
        cfg="$CLIENT_DIR/$name.toml"
        if [[ -r "$cfg" ]]; then
            addr=$(sed -n 's/^serverAddr *= *"\(.*\)"$/\1/p' "$cfg" | head -n1)
            port=$(sed -n 's/^serverPort *= *\([0-9]*\)$/\1/p' "$cfg" | head -n1)
        fi
        if [[ -z "${addr:-}" || -z "${port:-}" ]]; then
            continue
        fi
        if timeout 3 bash -c "exec 3<>/dev/tcp/$addr/$port" 2>/dev/null; then
            print_success "frpc@$name -> $addr:$port : reachable"
        else
            print_error "frpc@$name -> $addr:$port : UNREACHABLE"
        fi
    done
    if [[ "$found_frpc" == "0" ]]; then
        print_warning "No enabled frpc instances."
    fi

    echo "----------------------------------------"
    for cfgfile in "$SERVER_DIR"/*.toml; do
        if [[ ! -e "$cfgfile" ]]; then
            break
        fi
        bp=$(sed -n 's/^bindPort *= *\([0-9]*\)$/\1/p' "$cfgfile" | head -n1)
        if [[ -z "$bp" ]]; then
            continue
        fi
        if port_in_use "$bp"; then
            print_success "frps $(basename "$cfgfile"): listening on :$bp"
        else
            print_error "frps $(basename "$cfgfile"): NOT listening on :$bp"
        fi
    done
}

# --- Main menu (items 1-9 unchanged from v1; 10-13 are the suite additions) ----
main_menu() {
    while true; do
        clear
        print_header

        echo "1) Install FRP"
        echo "2) Setup FRP Server"
        echo "3) Setup FRP Client"
        echo "4) Advanced Configuration"
        echo "5) Show Status"
        echo "6) Stop All Services"
        echo "7) Optimization Utilities (Turbo)"
        echo "8) Remove FRP"
        echo "9) Exit"
        echo "10) GRE Tunnel Manager"
        echo "11) Web Panel"
        echo "12) Backup / Restore"
        echo "13) Watchdog & Health"
        echo "14) FRP over GRE Reverse (Quick Setup)"
        echo

        read -p "Choose an option [1-14]: " choice
        echo

        case $choice in
            1)
                install_frp
                pause
                ;;
            2)
                setup_server
                pause
                ;;
            3)
                setup_client
                read -p "Press Enter to continue..."
                ;;
            4)
                advanced_config
                pause
                ;;
            5)
                show_status
                pause
                ;;
            6)
                stop_services
                pause
                ;;
            7)
                utilities_menu
                ;;
            8)
                remove_frp
                pause
                ;;
            9)
                print_success "Goodbye!"
                exit 0
                ;;
            10)
                gre_menu
                ;;
            11)
                panel_menu
                ;;
            12)
                backup_menu
                ;;
            13)
                watchdog_menu
                ;;
            14)
                reverse_menu
                ;;
            *)
                print_error "Invalid option. Please choose 1-14."
                pause
                ;;
        esac
    done
}

# --- Non-interactive CLI ----------------------------------------------------------

cli_usage() {
    cat <<'USAGE'
frp-manager — FRP Tunnel Suite CLI

Interactive menu:
  frp-manager

Subcommands (non-interactive):
  frp-manager gre list
  frp-manager gre create --local-public IP --remote-public IP
                          [--iface gt11] [--local-private 10.100.111.1/30]
                          [--remote-private 10.100.111.2/30] [--mtu 1320]
                          [--mss clamp|1360|1240|1220|off] [--txqueuelen 1000]
  frp-manager gre delete <name>
  frp-manager gre mirror <name>
  frp-manager reverse iran --iran-public IP --foreign-public IP
                           [--iface gt11] [--control-port 7025]
                           [--protocol tcp|quic|kcp] [--mss 1220] [--txqueuelen 1000] [--no-watchdog]
                           (busy iface/subnet/port auto-allocate the next free value)
  frp-manager reverse foreign --payload FILE|- --ports 8443,2053,443
                           [--proto both|tcp|udp] [--local-ip 127.0.0.1] [--no-watchdog]
  frp-manager reverse foreign --local-public IP --remote-public IP
                           --control-port 7025 --token TOKEN
                           --ports 8443,2053,443 [--protocol tcp] [--no-watchdog]
  frp-manager panel install [--file <tar.gz>] [--port N]
  frp-manager panel start|stop|restart|status
  frp-manager panel port <N>
  frp-manager panel uninstall
  frp-manager turbo apply|revert|status
  frp-manager turbo zram-on [--size 2048] [--algo lz4]
  frp-manager turbo zram-off|zram-status
  frp-manager backup export [path]
  frp-manager backup import <path>
  frp-manager watchdog enable [--interval 15] [--threshold 3] [--cooldown 60]
                               [--tg-token TOKEN] [--tg-chat CHAT_ID]
                               [--tg-api-base URL] [--clear-telegram]
  frp-manager watchdog telegram [--token TOKEN] [--chat CHAT_ID] [--api-base URL]
  frp-manager watchdog test-telegram
  frp-manager watchdog disable|status
  frp-manager health
  frp-manager status
  frp-manager version

Environment:
  FRP_PANEL_RELEASE_BASE   override panel release download base URL
  FRP_SETUP_SOURCE_URL     install the CLI itself from a remote URL
USAGE
}

cli_dispatch() {
    NONINT=1
    local cmd="${1:-}"
    shift || true
    case "$cmd" in
        gre) gre_cli "$@" ;;
        reverse|wizard) reverse_cli "$@" ;;
        panel) panel_cli "$@" ;;
        turbo) turbo_cli "$@" ;;
        backup) backup_cli "$@" ;;
        watchdog) watchdog_cli "$@" ;;
        health) health_check ;;
        status) show_status ;;
        version|--version) echo "frp-manager $VERSION (FRP Tunnel Suite)" ;;
        help|-h|--help) cli_usage ;;
        *)
            print_error "unknown command: $cmd"
            cli_usage
            exit 1
            ;;
    esac
}

gre_cli() {
    local action="${1:-}"
    shift || true
    case "$action" in
        list) gre_list ;;
        create)
            local lp="" rp="" iface="gt11" lpriv="10.100.111.1/30" rpriv="10.100.111.2/30" mtu="1320" mss="clamp" txq="1000"
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --local-public) lp="$2"; shift 2 ;;
                    --remote-public) rp="$2"; shift 2 ;;
                    --iface) iface="$2"; shift 2 ;;
                    --local-private) lpriv="$2"; shift 2 ;;
                    --remote-private) rpriv="$2"; shift 2 ;;
                    --mtu) mtu="$2"; shift 2 ;;
                    --mss) mss="$2"; shift 2 ;;
                    --txqueuelen) txq="$2"; shift 2 ;;
                    *) print_error "unknown flag: $1"; exit 1 ;;
                esac
            done
            gre_create_do "$lp" "$rp" "$iface" "$lpriv" "$rpriv" "$mtu" "$mss" "$txq"
            ;;
        delete)
            [[ -n "${1:-}" ]] || { print_error "usage: frp-manager gre delete <name>"; exit 1; }
            gre_delete_do "$1"
            ;;
        mirror)
            [[ -n "${1:-}" ]] || { print_error "usage: frp-manager gre mirror <name>"; exit 1; }
            gre_mirror_print "$1"
            ;;
        *)
            print_error "usage: frp-manager gre list|create|delete|mirror"
            exit 1
            ;;
    esac
}

panel_cli() {
    local action="${1:-}"
    shift || true
    case "$action" in
        install)
            local file="" port=""
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --file) file="$2"; shift 2 ;;
                    --port) port="$2"; shift 2 ;;
                    *) print_error "unknown flag: $1"; exit 1 ;;
                esac
            done
            panel_install "$file"
            if [[ -n "$port" ]]; then
                if [[ -f "$PANEL_CONF_DIR/panel.toml" ]]; then
                    sed -i "s/^port *=.*/port = $port/" "$PANEL_CONF_DIR/panel.toml"
                    systemctl restart frp-panel
                    panel_open_firewall
                    print_success "Panel port set to $port."
                else
                    print_warning "panel.toml not generated yet — start the panel once, then re-run: frp-manager panel port $port"
                fi
            fi
            ;;
        start) systemctl start frp-panel && print_success "Panel started." ;;
        stop) systemctl stop frp-panel && print_success "Panel stopped." ;;
        restart) systemctl restart frp-panel && print_success "Panel restarted." ;;
        status) panel_info ;;
        port)
            [[ -n "${1:-}" ]] || { print_error "usage: frp-manager panel port <N>"; exit 1; }
            if ! is_valid_port "$1"; then print_error "invalid port"; exit 1; fi
            if [[ ! -f "$PANEL_CONF_DIR/panel.toml" ]]; then
                print_error "$PANEL_CONF_DIR/panel.toml not found — start the panel once first."
                exit 1
            fi
            sed -i "s/^port *=.*/port = $1/" "$PANEL_CONF_DIR/panel.toml"
            systemctl restart frp-panel
            panel_open_firewall
            print_success "Panel port set to $1."
            ;;
        uninstall)
            systemctl disable --now frp-panel 2>/dev/null || true
            rm -f /usr/local/bin/frp-panel /etc/systemd/system/frp-panel.service
            systemctl daemon-reload
            print_success "Web Panel uninstalled (config kept at $PANEL_CONF_DIR)."
            ;;
        *)
            print_error "usage: frp-manager panel install|start|stop|restart|status|port|uninstall"
            exit 1
            ;;
    esac
}

turbo_cli() {
    local action="${1:-}"
    shift || true
    case "$action" in
        apply) turbo_apply ;;
        revert) turbo_revert ;;
        status) /usr/local/bin/frp-turbo status 2>/dev/null || print_error "turbo not installed (run: frp-manager turbo apply)" ;;
        zram-on)
            local size="2048" algo="lz4"
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --size) size="$2"; shift 2 ;;
                    --algo) algo="$2"; shift 2 ;;
                    *) print_error "unknown flag: $1"; exit 1 ;;
                esac
            done
            zram_on "$size" "$algo"
            ;;
        zram-off) zram_off ;;
        zram-status) /usr/local/bin/frp-turbo zram-status 2>/dev/null || print_warning "frp-turbo not installed" ;;
        gc-cron|gc-status|volatile-logs|clear-logs)
            ensure_turbo_assets
            /usr/local/bin/frp-turbo "$action"
            ;;
        *)
            print_error "usage: frp-manager turbo apply|revert|status|zram-on|zram-off|zram-status|gc-cron|gc-status|volatile-logs|clear-logs"
            exit 1
            ;;
    esac
}

backup_cli() {
    local action="${1:-}"
    shift || true
    case "$action" in
        export) backup_export "${1:-}" ;;
        import)
            [[ -n "${1:-}" ]] || { print_error "usage: frp-manager backup import <path>"; exit 1; }
            backup_import "$1"
            ;;
        *)
            print_error "usage: frp-manager backup export [path] | import <path>"
            exit 1
            ;;
    esac
}

watchdog_cli() {
    local action="${1:-}"
    shift || true
    case "$action" in
        enable)
            local interval="15" threshold="3" cooldown="60"
            local tg_token="__KEEP__" tg_chat="__KEEP__" tg_api="__KEEP__"
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --interval) interval="$2"; shift 2 ;;
                    --threshold) threshold="$2"; shift 2 ;;
                    --cooldown) cooldown="$2"; shift 2 ;;
                    --tg-token) tg_token="$2"; shift 2 ;;
                    --tg-chat) tg_chat="$2"; shift 2 ;;
                    --tg-api-base) tg_api="$2"; shift 2 ;;
                    --clear-telegram) tg_token=""; tg_chat=""; tg_api="https://api.telegram.org"; shift ;;
                    *) print_error "unknown flag: $1"; exit 1 ;;
                esac
            done
            watchdog_enable "$interval" "$threshold" "$cooldown" "$tg_token" "$tg_chat" "$tg_api"
            ;;
        telegram)
            local token="__KEEP__" chat="__KEEP__" base="__KEEP__"
            local interval="15" threshold="3" cooldown="60"
            if [[ -r "$PANEL_CONF_DIR/watchdog.env" ]]; then
                # shellcheck disable=SC1090
                source "$PANEL_CONF_DIR/watchdog.env"
                interval="${INTERVAL:-15}"; threshold="${THRESHOLD:-3}"; cooldown="${COOLDOWN:-60}"
            fi
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --token) token="$2"; shift 2 ;;
                    --chat) chat="$2"; shift 2 ;;
                    --api-base) base="$2"; shift 2 ;;
                    *) print_error "unknown flag: $1"; exit 1 ;;
                esac
            done
            watchdog_enable "$interval" "$threshold" "$cooldown" "$token" "$chat" "$base"
            ;;
        test-telegram) watchdog_telegram_test ;;
        disable) watchdog_disable ;;
        status) watchdog_status ;;
        *)
            print_error "usage: frp-manager watchdog enable|telegram|test-telegram|disable|status"
            exit 1
            ;;
    esac
}

# --- Entry -------------------------------------------------------------------------

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root (use sudo)"
    exit 1
fi

if [[ $# -eq 0 ]]; then
    # Interactive mode (self-install + BBR ensure, preserved from v1;
    # the installed copy comments these two lines out via sed)
install_script
optimize
    main_menu
else
    cli_dispatch "$@"
fi
