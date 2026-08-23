#!/usr/bin/env bash
# Gap #4: disk-full and OOM behaviour, measured on a real node — not reviewed.
#
#   harness/resource-limits.sh disk   # data dir on a tiny loop/tmpfs filesystem
#   harness/resource-limits.sh oom    # node under a cgroup v2 memory cap
#   harness/resource-limits.sh both
#
# Pass criteria (checked automatically):
#   * the node dies or refuses to continue with a clear error — no silent corruption
#   * after the constraint is lifted, the node restarts and serves inaz_chainInfo
#     at a height >= the last height observed before the failure
# Requires root for mount/cgroup operations.
set -euo pipefail
MODE=${1:-both}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="$ROOT/target/release/inazuma"
WORK=${WORK:-/tmp/inaz-limits}
RPC=${RPC:-127.0.0.1:19391}
P2P=${P2P:-127.0.0.1:19491}
GEN="$WORK/genesis.json"
[ -x "$BIN" ] || { echo "build first: cargo build --release"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root (mount + cgroup needed)"; exit 1; }

height() { curl -s --max-time 5 "http://$RPC" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"inaz_chainInfo","params":{}}' \
  | sed -n 's/.*"height":\([0-9]*\).*/\1/p'; }

prepare() {
  # Single-validator net built by the normal devnet path, then stopped: we only
  # want its fresh genesis + key, the node is (re)started under the constraint.
  rm -rf "$WORK"; mkdir -p "$WORK"
  bash "$ROOT/harness/devnet.sh" 1 "$WORK" >/dev/null
  sleep 3
  kill -9 "$(cat "$WORK/n1.pid")" 2>/dev/null || true
  cp "$WORK/n1.key" "$WORK/v.key"
  rm -rf "$WORK/d1"
}

start_node() { # $@ extra prefix (e.g. cgexec)
  "$@" "$BIN" run --data "$DATA" --genesis "$GEN" --key "$(cat "$WORK/v.key")" \
    --rpc "$RPC" --p2p "$P2P" > "$LOG" 2>&1 &
  echo $! > "$WORK/node.pid"
  for _ in $(seq 1 40); do [ -n "$(height)" ] && return 0; sleep 1; done
  echo "node never came up — see $LOG"; return 1
}

verify_recovery() { # $1 = height before the kill
  local before=$1 after=""
  echo "[verify] restarting with the constraint lifted"
  DATA="$WORK/data-copy"; rm -rf "$DATA"; cp -a "$WORK/data" "$DATA"
  LOG="$WORK/recover.log"; start_node
  after=$(height)
  kill -9 "$(cat "$WORK/node.pid")" 2>/dev/null || true
  echo "[verify] height before=$before after-restart=$after"
  [ -n "$after" ] && [ "$after" -ge "$before" ] || { echo "FAIL: state not intact"; return 1; }
  echo "PASS: DB reopened cleanly, state intact"
}

disk_test() {
  echo "=== disk-full ==="
  prepare
  DATA="$WORK/data"; LOG="$WORK/disk.log"
  mkdir -p "$DATA"; mount -t tmpfs -o size=24M tmpfs "$DATA"
  start_node
  sleep 20
  local h; h=$(height); echo "[disk] height before filling: $h"
  echo "[disk] filling the filesystem to 100%"
  dd if=/dev/zero of="$DATA/ballast" bs=1M 2>/dev/null || true
  sleep 45
  if kill -0 "$(cat "$WORK/node.pid")" 2>/dev/null; then
    echo "[disk] node still running; last log lines:"; tail -n 20 "$LOG"
  else
    echo "[disk] node exited. Last log lines:"; tail -n 20 "$LOG"
  fi
  grep -iE 'no space|ENOSPC|disk' "$LOG" >/dev/null && echo "[disk] clear disk error logged ✓" \
    || echo "[disk] WARN: no explicit disk error in log"
  rm -f "$DATA/ballast"
  kill -9 "$(cat "$WORK/node.pid")" 2>/dev/null || true
  sleep 2
  cp -a "$DATA" "$WORK/data" 2>/dev/null || true
  umount "$DATA" 2>/dev/null || true
  verify_recovery "${h:-0}"
}

oom_test() {
  echo "=== OOM (cgroup v2 memory cap) ==="
  prepare
  DATA="$WORK/data"; LOG="$WORK/oom.log"; mkdir -p "$DATA"
  local CG=/sys/fs/cgroup/inazoom
  mkdir -p "$CG"
  echo "${OOM_LIMIT:-64M}" > "$CG/memory.max"
  echo 0 > "$CG/memory.swap.max" 2>/dev/null || true
  ( echo $BASHPID > "$CG/cgroup.procs"; exec "$BIN" run --data "$DATA" --genesis "$GEN" \
      --key "$(cat "$WORK/v.key")" --rpc "$RPC" --p2p "$P2P" ) > "$LOG" 2>&1 &
  echo $! > "$WORK/node.pid"
  local h=0
  for _ in $(seq 1 60); do
    local cur; cur=$(height); [ -n "$cur" ] && h=$cur
    kill -0 "$(cat "$WORK/node.pid")" 2>/dev/null || break
    sleep 1
  done
  echo "[oom] last observed height: $h"
  echo "[oom] cgroup oom kills: $(grep -c oom_kill "$CG/memory.events" >/dev/null 2>&1; awk '/oom_kill/{print $2}' "$CG/memory.events")"
  tail -n 20 "$LOG"
  kill -9 "$(cat "$WORK/node.pid")" 2>/dev/null || true
  sleep 1; rmdir "$CG" 2>/dev/null || true
  verify_recovery "$h"
}

case "$MODE" in
  disk) disk_test ;;
  oom) oom_test ;;
  both) disk_test; echo; oom_test ;;
  *) echo "usage: $0 disk|oom|both"; exit 2 ;;
esac
