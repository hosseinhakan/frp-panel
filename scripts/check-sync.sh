#!/usr/bin/env bash
# check-sync.sh — guards the "single source" rule for system assets.
#
# frp-setup.sh embeds byte-identical heredoc copies of every unit/helper that
# also lives in panel/internal/assets/ (and is embedded in the Go binary).
# This script fails when the two copies drift.
#
# Usage: scripts/check-sync.sh [path-to-frp-setup.sh]
set -uo pipefail

CLI="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/frp-setup.sh}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSETS="$ROOT/panel/internal/assets"

# heredoc tag -> path relative to panel/internal/assets/
mapfile -t PAIRS <<'MAP'
ASSET_FRPS_SERVICE systemd/frps@.service
ASSET_FRPC_SERVICE systemd/frpc@.service
ASSET_GRE_TUNNEL_SERVICE systemd/gre-tunnel@.service
ASSET_TUNNEL_TURBO_SERVICE systemd/tunnel-turbo.service
ASSET_FRP_ZRAM_SERVICE systemd/frp-zram.service
ASSET_FRP_WATCHDOG_SERVICE systemd/frp-watchdog.service
ASSET_FRP_PANEL_SERVICE systemd/frp-panel.service
ASSET_FRP_GRE helpers/frp-gre
ASSET_FRP_TURBO helpers/frp-turbo
ASSET_FRP_WATCHDOG helpers/frp-watchdog
MAP

fail=0
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

for pair in "${PAIRS[@]}"; do
    tag="${pair%% *}"
    rel="${pair#* }"
    file="$ASSETS/$rel"

    if [[ ! -f "$CLI" ]]; then
        echo "MISSING CLI file: $CLI"
        exit 1
    fi
    if [[ ! -f "$file" ]]; then
        echo "MISSING asset file: $file (tag $tag)"
        fail=1
        continue
    fi

    # Extract heredoc body: from the line containing <<'tag' to the delimiter.
    awk -v m="<<'${tag}'" -v t="$tag" '
        index($0, m) { ingest = 1; next }
        ingest && $0 == t { exit }
        ingest { print }
    ' "$CLI" > "$tmp"

    if cmp -s "$tmp" "$file"; then
        echo "ok    $tag -> $rel"
    elif [[ ! -s "$tmp" ]]; then
        echo "DRIFT $tag -> $rel: heredoc not found in $CLI"
        fail=1
    else
        echo "DRIFT $tag -> $rel: heredoc differs from canonical asset"
        diff -u "$file" "$tmp" | head -n 20
        fail=1
    fi
done

if (( fail )); then
    echo "check-sync: FAILED — re-copy the canonical asset into the frp-setup.sh heredoc"
    exit 1
fi
echo "check-sync: all heredocs match canonical assets"
