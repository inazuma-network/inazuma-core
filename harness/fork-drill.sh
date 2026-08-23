#!/usr/bin/env bash
# Gap #1 acceptance drill: deliberately create disagreement between nodes and
# measure how long forkwatch takes to page. Passes only if the alert fires
# within ALERT_SLA_S (default 60s).
#
# Usage: harness/fork-drill.sh [n-validators]
#
# How the fork is forced without touching consensus code: the devnet is split
# into two halves with a firewall-free trick — each half is restarted with only
# its own peers, so both halves keep producing on top of the same history and
# their tips diverge. forkwatch sees two different state roots at the common
# height and must page.
set -euo pipefail
N=${1:-4}
WORK=${WORK:-/tmp/forkdrill}
SLA=${ALERT_SLA_S:-60}
ROOT=$(cd "$(dirname "$0")/.." && pwd)

rm -rf "$WORK"; mkdir -p "$WORK"
WORK="$WORK" bash "$ROOT/harness/devnet.sh" "$N" "$WORK" >/dev/null
sleep 10

URLS=""
for i in $(seq 1 "$N"); do URLS="$URLS,http://127.0.0.1:$((19330+i))"; done
URLS=${URLS#,}

echo "[drill] starting forkwatch on $URLS"
NODE_URLS="$URLS" INTERVAL_MS=2000 STALL_MS=$((SLA * 1000)) ALERT_SOURCE="fork-drill" \
  node "$ROOT/harness/forkwatch.mjs" > "$WORK/forkwatch.log" 2>&1 &
WATCH=$!
START=$(date +%s)

echo "[drill] splitting the network into two halves"
HALF=$(( (N + 1) / 2 ))
split_half() { # $1=first index $2=last index
  local peers="" i
  for i in $(seq "$1" "$2"); do peers="$peers,127.0.0.1:$((19440+i))"; done
  peers=${peers#,}
  for i in $(seq "$1" "$2"); do
    kill -9 "$(cat "$WORK/n$i.pid")" 2>/dev/null || true
    sleep 0.3
    setsid nohup "$ROOT/target/release/inazuma" run \
      --data "$WORK/d$i" --genesis "$WORK/genesis.json" --key "$(cat "$WORK/n$i.key")" \
      --rpc "127.0.0.1:$((19330+i))" --p2p "127.0.0.1:$((19440+i))" --ws "127.0.0.1:$((19550+i))" \
      --peers "$peers" >> "$WORK/n$i.split.log" 2>&1 &
    echo $! > "$WORK/n$i.pid"
  done
}
split_half 1 "$HALF"
split_half $((HALF + 1)) "$N"

echo "[drill] waiting up to ${SLA}s for a fork/divergence alert"
DETECT=""
for _ in $(seq 1 "$SLA"); do
  if grep -qE 'FINALIZED-FORK|state-root-divergence|chain-stall' "$WORK/forkwatch.log"; then
    DETECT=$(( $(date +%s) - START )); break
  fi
  kill -0 "$WATCH" 2>/dev/null || { DETECT=$(( $(date +%s) - START )); break; }
  sleep 1
done

kill -9 "$WATCH" 2>/dev/null || true
for i in $(seq 1 "$N"); do kill -9 "$(cat "$WORK/n$i.pid")" 2>/dev/null || true; done

echo "---- forkwatch alerts ----"
grep -E '\[ALERT\]' "$WORK/forkwatch.log" || echo "(none)"
if [ -n "$DETECT" ] && [ "$DETECT" -le "$SLA" ]; then
  echo "[drill] PASS — alert fired in ${DETECT}s (SLA ${SLA}s)"
  exit 0
fi
echo "[drill] FAIL — no alert within ${SLA}s (log: $WORK/forkwatch.log)"
exit 1
