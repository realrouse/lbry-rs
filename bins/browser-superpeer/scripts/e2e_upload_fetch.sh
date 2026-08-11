#!/usr/bin/env bash
# Empty superpeer store → CLI upload → fetch → compare to source.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"
BIN="${BIN:-./target/release/browser-superpeer}"
if [[ ! -x "$BIN" ]]; then
  cargo build --release -p browser-superpeer
fi

SP_BLOBS=$(mktemp -d)
PACK=$(mktemp -d)
trap 'kill $(cat /tmp/lbry-rs-sp.pid 2>/dev/null) 2>/dev/null || true; rm -rf "$SP_BLOBS" "$PACK"' EXIT

"$BIN" pack --input fixtures/source_demo.wav --out "$PACK" >/dev/null
SD=$(python3 -c "import json;print(json.load(open('$PACK/DEMO.json'))['sd_hash'])")

"$BIN" superpeer --blobs "$SP_BLOBS" > /tmp/lbry-rs-sp.log 2>&1 &
echo $! > /tmp/lbry-rs-sp.pid
for _ in $(seq 1 80); do
  grep -q 'ticket      =' /tmp/lbry-rs-sp.log && break
  sleep 0.25
done
TICKET=$(sed -n 's/^  ticket      = //p' /tmp/lbry-rs-sp.log)
test -n "$TICKET"

"$BIN" upload --ticket "$TICKET" --blobs "$PACK"
"$BIN" fetch --ticket "$TICKET" --sd-hash "$SD" --out /tmp/lbry-rs-out.wav
cmp -s /tmp/lbry-rs-out.wav fixtures/source_demo.wav
echo "e2e upload→fetch OK ($(wc -c < fixtures/source_demo.wav) bytes)"
