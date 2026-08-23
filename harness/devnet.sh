#!/usr/bin/env bash
# Spin up a local Inazuma devnet of N validators (+1 read replica) from scratch.
# Usage: harness/devnet.sh <n-validators> [work-dir]
set -euo pipefail
N=${1:-4}
WORK=${2:-/tmp/devnet}
BIN=$(cd "$(dirname "$0")/.." && pwd)/target/release/inazuma
rm -rf "$WORK"; mkdir -p "$WORK"
echo "[devnet] $N validators in $WORK"

# --- keys ---
for i in $(seq 1 "$N"); do
  "$BIN" keygen | awk '/address:/{print $2 > "'"$WORK"'/n'"$i"'.addr"} /secret key:/{print $3 > "'"$WORK"'/n'"$i"'.key"}'
done

# --- genesis: every validator funded and bonded ---
{
  echo '{ "chain_id": 7777, "chain_name": "Inazuma", "symbol": "INAZ", "decimals": 9, "block_time_ms": 400,'
  # Fresh genesis: slashing and liveness accounting live from block 1, so
  # adversarial runs exercise the real code path instead of a dormant one.
  echo '  "slashing_activation_height": 1, "alloc": ['
  for i in $(seq 1 "$N"); do
    [ "$i" -gt 1 ] && echo ','
    printf '{ "address": "%s", "balance": "100000", "stake": "40000" }' "$(cat "$WORK/n$i.addr")"
  done
  # faucet / load-test treasury key (fixed for the harness)
  echo ", { \"address\": \"$(cat "$WORK/n1.addr")\", \"balance\": \"0\", \"stake\": null }"
  echo '] }'
} > "$WORK/genesis.json"

# --- peer wiring ---
PEERS=""
for i in $(seq 1 "$N"); do PEERS="$PEERS,127.0.0.1:$((19440+i))"; done
PEERS=${PEERS#,}

start_node() { # idx rpc p2p ws extra...
  local i=$1 rpc=$2 p2p=$3 ws=$4; shift 4
  mkdir -p "$WORK/d$i"
  INAZ_RPC_ADMIN_KEYS="${HARNESS_ADMIN_KEY:-harness-admin-key-0123456789}" \
  "$BIN" run --data "$WORK/d$i" --genesis "$WORK/genesis.json" \
    --key "$(cat "$WORK/n$i.key")" \
    --rpc "127.0.0.1:$rpc" --p2p "127.0.0.1:$p2p" --ws "127.0.0.1:$ws" \
    --peers "$PEERS" "$@" > "$WORK/n$i.log" 2>&1 &
  echo $! > "$WORK/n$i.pid"
}

for i in $(seq 1 "$N"); do
  start_node "$i" $((19330+i)) $((19440+i)) $((19550+i))
done
echo "[devnet] started; rpc ports $((19331))..$((19330+N))"
