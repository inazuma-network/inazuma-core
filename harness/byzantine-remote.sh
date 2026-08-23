#!/usr/bin/env bash
# Gap #3: adversarial validators as real, separately built binaries running on
# real remote machines against the honest multi-region net.
#
#   HONEST="user@a user@b user@c" ADVERSARY=user@d \
#   harness/byzantine-remote.sh double-sign
#
# modes: double-sign | equivocate | invalid | withhold
#
# What it does:
#   1. builds the malicious binary locally (`--features byzantine`)
#   2. ships it to the adversary host and swaps the running node's binary
#   3. watches the honest nodes: they must slash/jail the adversary AND keep
#      producing blocks throughout (no stall)
#   4. restores the honest binary on the adversary host
set -euo pipefail
MODE=${1:?mode required: double-sign|equivocate|invalid|withhold}
: "${HONEST:?set HONEST='user@host ...'}"
: "${ADVERSARY:?set ADVERSARY=user@host}"
WATCH_S=${WATCH_S:-300}
RPC_PORT=${RPC_PORT:-9933}
ROOT=$(cd "$(dirname "$0")/.." && pwd)

rpc() { # $1=host $2=method
  ssh "$1" "curl -s --max-time 5 http://127.0.0.1:$RPC_PORT -H 'content-type: application/json' \
    -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":{}}'"
}
h_of() { rpc "$1" inaz_chainInfo | sed -n 's/.*"height":\([0-9]*\).*/\1/p'; }

echo "[byz] building adversary binary (features=byzantine)"
( cd "$ROOT" && cargo build --release --features byzantine --target-dir target/byz )

echo "[byz] deploying to $ADVERSARY"
scp -q "$ROOT/target/byz/release/inazuma" "$ADVERSARY:/tmp/inazuma-byz"
ssh "$ADVERSARY" "sudo cp /usr/local/bin/inazuma /usr/local/bin/inazuma.honest.bak 2>/dev/null || true; \
  sudo install -m755 /tmp/inazuma-byz /usr/local/bin/inazuma; \
  sudo mkdir -p /etc/systemd/system/inazuma.service.d; \
  printf '[Service]\nEnvironment=INAZ_BYZANTINE=$MODE\n' | sudo tee /etc/systemd/system/inazuma.service.d/byz.conf >/dev/null; \
  sudo systemctl daemon-reload && sudo systemctl restart inazuma"

declare -A H0
for h in $HONEST; do H0[$h]=$(h_of "$h"); echo "[byz] honest $h at height ${H0[$h]}"; done

echo "[byz] adversary live in mode=$MODE — watching honest nodes for ${WATCH_S}s"
SLASHED=0
for _ in $(seq 1 "$WATCH_S"); do
  for h in $HONEST; do
    if rpc "$h" inaz_validators | grep -qiE '"jailed":true|"slashed"'; then SLASHED=1; fi
  done
  [ "$SLASHED" = 1 ] && break
  sleep 1
done

FAIL=0
for h in $HONEST; do
  now=$(h_of "$h"); before=${H0[$h]}
  if [ -z "$now" ] || [ "$now" -le "$before" ]; then echo "[byz] STALL on $h ($before -> ${now:-dead})"; FAIL=1
  else echo "[byz] $h kept producing: $before -> $now ✓"; fi
done
[ "$SLASHED" = 1 ] && echo "[byz] adversary detected and jailed/slashed ✓" || { echo "[byz] adversary NOT punished ✗"; FAIL=1; }

echo "[byz] restoring honest binary on $ADVERSARY"
ssh "$ADVERSARY" "sudo rm -f /etc/systemd/system/inazuma.service.d/byz.conf; \
  sudo cp /usr/local/bin/inazuma.honest.bak /usr/local/bin/inazuma 2>/dev/null || true; \
  sudo systemctl daemon-reload && sudo systemctl restart inazuma"

[ "$FAIL" = 0 ] && { echo "[byz] PASS mode=$MODE"; exit 0; }
echo "[byz] FAIL mode=$MODE"; exit 1
