#!/usr/bin/env bash
# vendor-web.sh — pin & fetch the panel's vendored frontend libraries.
#
# DEV-TIME ONLY: the checked-in files under panel/web/static/js/vendor/ are
# what ships (go:embed). Run this only to upgrade a library deliberately;
# it refuses to overwrite the tree unless every download matches the pinned
# sha256 below.
#
# Layout after a run (all committed to the repo — the panel never fetches
# anything at runtime):
#   panel/web/static/js/vendor/alpine.min.js     Alpine.js 3.14.9
#   panel/web/static/js/vendor/htmx.min.js       htmx 1.9.12
#   panel/web/static/js/vendor/htmx-sse.min.js   htmx 1.9.12 sse extension
#   panel/web/static/js/vendor/uPlot.min.js      uPlot 1.6.32 (IIFE build)
#   panel/web/static/css/uPlot.min.css           uPlot 1.6.32
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
jsdir="$root/panel/web/static/js/vendor"
cssdir="$root/panel/web/static/css"
mkdir -p "$jsdir" "$cssdir"

fetch() { # fetch <url> <sha256> <dest>
    local url="$1" want="$2" dest="$3" tmp
    tmp="$(mktemp)"
    echo "==> $url"
    curl -fsSL --retry 2 "$url" -o "$tmp"
    local got
    got="$(sha256sum "$tmp" | awk '{print $1}')"
    if [[ "$(echo "$got" | tr 'A-F' 'a-f')" != "$(echo "$want" | tr 'A-F' 'a-f')" ]]; then
        rm -f "$tmp"
        echo "sha256 mismatch for $url" >&2
        echo "  want $want" >&2
        echo "  got  $got" >&2
        exit 1
    fi
    mv "$tmp" "$dest"
    echo "    ok $(basename "$dest") ($want)"
}

fetch "https://cdn.jsdelivr.net/npm/alpinejs@3.14.9/dist/cdn.min.js" \
      "3ed1eed252488921df65e363d6715deb04d7f92aaedb9e52199fdf73cb1e0ad3" \
      "$jsdir/alpine.min.js"

fetch "https://cdn.jsdelivr.net/npm/htmx.org@1.9.12/dist/htmx.min.js" \
      "449317ade7881e949510db614991e195c3a099c4c791c24dacec55f9f4a2a452" \
      "$jsdir/htmx.min.js"

fetch "https://cdn.jsdelivr.net/npm/htmx.org@1.9.12/dist/ext/sse.js" \
      "be05b2e2265279f035271adbea0b72a356f20ce4dfa5870481bfe9c51b822fc1" \
      "$jsdir/htmx-sse.min.js"

fetch "https://cdn.jsdelivr.net/npm/uplot@1.6.32/dist/uPlot.iife.min.js" \
      "19c8d4c6ad88929a79f4ae49d6f7161566dfd0ba3d15cc495e974f787eb78f1f" \
      "$jsdir/uPlot.min.js"

fetch "https://cdn.jsdelivr.net/npm/uplot@1.6.32/dist/uPlot.min.css" \
      "df630c6a8d6f8eeaff264b50f73ce5b114f646ffd9a0bb74f049b0a00135fa04" \
      "$cssdir/uPlot.min.css"

echo "vendor-web: all five assets verified against their pins."
echo "commit the files if anything changed (git diff panel/web/static)."
