#!/usr/bin/env bash
# verify.sh — one-shot P9 verification battery (mirrors CI).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
fail=0

step() { echo; echo "==> $*"; }

step "bash syntax gate"
bash -n frp-setup.sh || fail=1
for f in scripts/*.sh; do bash -n "$f" || fail=1; done
echo "syntax OK (frp-setup.sh + $(ls scripts/*.sh | wc -l) scripts)"

step "heredoc/asset sync"
./scripts/check-sync.sh || fail=1

step "vendored JS pin verification"
./scripts/vendor-web.sh || fail=1

step "go vet + go test"
export PATH="/c/Program Files/Go/bin:$PATH"
cd panel
go vet ./... || fail=1
go test -count=1 ./... || fail=1
cd ..

step "release build (v1.0.0)"
./scripts/build-release.sh 1.0.0 || fail=1

echo
if (( fail )); then
  echo "verify: FAILED"
  exit 1
fi
echo "verify: ALL GREEN"
