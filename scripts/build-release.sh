#!/usr/bin/env bash
# build-release.sh — cross-compile frp-panel and package release tarballs.
# Artifacts (stable filenames, consumed by the CLI panel installer and the
# one-line curl installer):
#   dist/frp-panel_linux_amd64.tar.gz      + .sha256 sidecar
#   dist/frp-panel_linux_arm64.tar.gz      + .sha256 sidecar
#
# Each tarball contains ./frp-panel and ./install.sh (the curl target).
#
# Usage: scripts/build-release.sh [version]
set -euo pipefail

VERSION="${1:-dev}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/dist"
mkdir -p "$OUT"

cd "$ROOT/panel"
go vet ./...
go test ./...

for arch in amd64 arm64; do
    stage="$OUT/frp-panel_linux_$arch"
    rm -rf "$stage"
    mkdir -p "$stage"
    echo "==> building linux/$arch (version $VERSION)"
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
        go build -trimpath -ldflags "-s -w -X main.version=$VERSION" \
        -o "$stage/frp-panel" ./cmd/frp-panel
    if [[ -f "$ROOT/scripts/install.sh" ]]; then
        cp "$ROOT/scripts/install.sh" "$stage/"
    else
        echo "    note: scripts/install.sh missing — tarball ships binary only"
    fi
    tarball="$OUT/frp-panel_linux_$arch.tar.gz"
    if [[ -f "$ROOT/scripts/install.sh" ]]; then
        tar -czf "$tarball" -C "$stage" frp-panel install.sh
    else
        tar -czf "$tarball" -C "$stage" frp-panel
    fi
    (
        cd "$OUT"
        sha256sum "frp-panel_linux_$arch.tar.gz" > "frp-panel_linux_$arch.tar.gz.sha256"
    )
    echo "    -> $tarball ($(du -h "$tarball" | cut -f1))"
done

echo "==> done. artifacts:"
ls -la "$OUT"/*.{tar.gz,tar.gz.sha256} 2>/dev/null | awk '{print "    " $NF " (" $5 " bytes)"}'
