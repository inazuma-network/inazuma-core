#!/usr/bin/env bash
# Adversarial validator run: honest devnet + one node replaced by a real
# malicious binary (separate process, separate build, real sockets).
#
# Usage: harness/byzantine.sh <mode> [n-validators]
#   mode: double-sign | equivocate | invalid | withhold
set -euo pipefail
MODE=${1:?mode required: double-sign|equivocate|invalid|withhold}
N=${2:-4}
WORK=${WORK:-/tmp/byznet}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="$ROOT/target/release/inazuma"
BYZ="$ROOT/target/release/inazuma-byz"
[ -x "$BYZ" ] || { echo "build it first: cargo build --release --features byzantine --target-dir target/byz && cp target/byz/release/inazuma target/release/inazuma-byz"; exit 1; }

WORK="$WORK" bash "$ROOT/harness/devnet.sh" "$N" "$WORK" >/dev/null
sleep 8

# Node N becomes the attacker: same key, same data dir, malicious binary.
kill -9 "$(cat "$WORK/n$N.pid")" 2>/dev/null || true
sleep 1
PEERS=""
for i in $(seq 1 "$N"); do PEERS="$PEERS,127.0.0.1:$((19440+i))"; done
PEERS=${PEERS#,}
INAZ_BYZANTINE="$MODE" \
INAZ_RPC_ADMIN_KEYS="${HARNESS_ADMIN_KEY:-harness-admin-key-0123456789}" \
setsid nohup "$BYZ" run --data "$WORK/d$N" --genesis "$WORK/genesis.json" \
  --key "$(cat "$WORK/n$N.key")" \
  --rpc "127.0.0.1:$((19330+N))" --p2p "127.0.0.1:$((19440+N))" --ws "127.0.0.1:$((19550+N))" \
  --peers "$PEERS" > "$WORK/n$N.byz.log" 2>&1 &
echo $! > "$WORK/n$N.pid"
echo "[byz] node $N restarted as ADVERSARY mode=$MODE (log $WORK/n$N.byz.log)"
