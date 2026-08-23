#!/usr/bin/env bash
# Restart a single devnet node in place, reusing its existing data dir so this
# exercises real crash recovery rather than a fresh sync.
set -euo pipefail
i=${1:?node index}
WORK=${WORK:-/tmp/devnet}
BIN=$(cd "$(dirname "$0")/.." && pwd)/target/release/inazuma
N=${NODES:-4}
PEERS=""; for k in $(seq 1 "$N"); do PEERS="$PEERS,127.0.0.1:$((19440+k))"; done; PEERS=${PEERS#,}
INAZ_RPC_ADMIN_KEYS="${HARNESS_ADMIN_KEY:-harness-admin-key-0123456789}" \
"$BIN" run --data "$WORK/d$i" --genesis "$WORK/genesis.json" \
  --key "$(cat "$WORK/n$i.key")" \
  --rpc "127.0.0.1:$((19330+i))" --p2p "127.0.0.1:$((19440+i))" --ws "127.0.0.1:$((19550+i))" \
  --peers "$PEERS" >> "$WORK/n$i.log" 2>&1 &
echo $! > "$WORK/n$i.pid"
