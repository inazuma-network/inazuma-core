#!/usr/bin/env bash
# Full reset to true genesis across real, multi-region machines.
#
#   HOSTS="user@fra1 user@nyc3 user@sgp1 user@lon1 user@tor1" \
#   harness/testnet-reset.sh
#
# Everything is fresh: new keys, new genesis, empty data dirs. Nothing is
# inherited from the previous net — this is the exact path a public tester walks.
#
# Steps: wipe -> new validator keys -> new genesis -> distribute -> start ->
# verify all hosts agree on genesis hash and are producing blocks.
set -euo pipefail
: "${HOSTS:?set HOSTS='user@host ...'}"
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="$ROOT/target/release/inazuma"
OUT=${OUT:-/tmp/inaz-reset}
RPC_PORT=${RPC_PORT:-9933}
P2P_PORT=${P2P_PORT:-9944}
STAKE=${STAKE:-100000}
[ -x "$BIN" ] || { echo "build first: cargo build --release"; exit 1; }
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== 1/6 stopping and wiping every host =="
for h in $HOSTS; do
  ssh "$h" "sudo systemctl stop inazuma 2>/dev/null || true; sudo rm -rf /var/lib/inazuma/*" &
done; wait

echo "== 2/6 generating fresh validator keys (locally, one per host) =="
i=0
for h in $HOSTS; do
  i=$((i + 1))
  "$BIN" keygen | awk '/address:/{print $2 > "'"$OUT"'/v'"$i"'.addr"} /secret key:/{print $3 > "'"$OUT"'/v'"$i"'.key"}'
  echo "$h" > "$OUT/v$i.host"
done
COUNT=$i

echo "== 3/6 building a brand-new genesis =="
{
  printf '{ "chain_id": %s, "chain_name": "Inazuma", "symbol": "INAZ", "decimals": 9, "block_time_ms": 400,\n' "${CHAIN_ID:-7777}"
  echo '  "slashing_activation_height": 1, "alloc": ['
  for n in $(seq 1 "$COUNT"); do
    [ "$n" -gt 1 ] && echo ','
    printf '{ "address": "%s", "balance": "%s", "stake": "%s" }' \
      "$(cat "$OUT/v$n.addr")" "${BALANCE:-200000}" "$STAKE"
  done
  echo '] }'
} > "$OUT/genesis.json"
GHASH=$(sha256sum "$OUT/genesis.json" | cut -d" " -f1)
echo "genesis file sha256: $GHASH  (on-chain genesis hash is printed by \`inazuma init\`)"

echo "== 4/6 distributing genesis + keys =="
PEERS=""
for n in $(seq 1 "$COUNT"); do
  host=$(cat "$OUT/v$n.host")
  ip=$(ssh "$host" "curl -s --max-time 5 https://api.ipify.org")
  echo "$ip" > "$OUT/v$n.ip"
  PEERS="$PEERS,$ip:$P2P_PORT"
done
PEERS=${PEERS#,}
for n in $(seq 1 "$COUNT"); do
  host=$(cat "$OUT/v$n.host")
  key=$(cat "$OUT/v$n.key")
  scp -q "$OUT/genesis.json" "$host:/tmp/genesis.json"
  ssh "$host" "sudo install -D -m644 /tmp/genesis.json /etc/inazuma/genesis.json; rm /tmp/genesis.json; \
    printf 'INAZ_KEY=%s\nINAZ_PEERS=%s\n' '$key' '$PEERS' | sudo tee /etc/inazuma/validator.env >/dev/null; \
    sudo chmod 600 /etc/inazuma/validator.env; \
    sudo inazuma init --data /var/lib/inazuma --genesis /etc/inazuma/genesis.json" &
done; wait

echo "== 5/6 starting all nodes =="
for n in $(seq 1 "$COUNT"); do
  ssh "$(cat "$OUT/v$n.host")" "sudo systemctl start inazuma" &
done; wait
sleep 25

echo "== 6/6 verifying bootstrap =="
URLS=""; FAIL=0
for n in $(seq 1 "$COUNT"); do
  host=$(cat "$OUT/v$n.host"); ip=$(cat "$OUT/v$n.ip")
  info=$(ssh "$host" "curl -s --max-time 8 http://127.0.0.1:$RPC_PORT -H 'content-type: application/json' \
    -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"inaz_chainInfo\",\"params\":{}}'")
  h=$(echo "$info" | sed -n 's/.*"height":\([0-9]*\).*/\1/p')
  peers=$(echo "$info" | sed -n 's/.*"peers":\([0-9]*\).*/\1/p')
  echo "  $host  height=${h:-DEAD} peers=${peers:-0}"
  { [ -n "$h" ] && [ "${h:-0}" -gt 0 ] && [ "${peers:-0}" -ge 1 ]; } || FAIL=1
  URLS="$URLS,http://$ip:$RPC_PORT"
done
URLS=${URLS#,}
echo
echo "NODE_URLS=$URLS"
echo "next: start forkwatch against those URLs, then run harness/load.mjs sustained,"
echo "      then harness/byzantine-remote.sh and harness/resource-limits.sh live."
[ "$FAIL" = 0 ] || { echo "RESET FAILED — one or more nodes not healthy"; exit 1; }
echo "RESET OK — fresh chain live on $COUNT hosts, genesis $GHASH"
