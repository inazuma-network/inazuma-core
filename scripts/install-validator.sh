#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Inazuma validator installer
#
#   curl -sSf https://raw.githubusercontent.com/inazuma-network/inazuma-core/main/scripts/install-validator.sh | bash
#
# What it does, in order:
#   1. checks the machine is big enough
#   2. installs build tools + Rust (if missing)
#   3. builds the inazuma binary and installs it to /usr/local/bin
#   4. creates a validator key (or reuses the one you already have)
#   5. writes /etc/inazuma/genesis.json and initialises the data directory
#   6. installs a systemd service that restarts on crash and on reboot
#   7. prints your address and the single command needed to bond stake
#
# It never prints your secret key to the terminal log; the key is written to
# /etc/inazuma/validator.env with mode 600 and shown once at the end.
#
# Re-running is safe: it upgrades the binary and leaves keys and data alone.
# ---------------------------------------------------------------------------
set -euo pipefail

REPO_URL="${INAZ_REPO:-https://github.com/inazuma-network/inazuma-core.git}"
SEED="${INAZ_PEERS:-rpc.inazuma.network:9944}"
ROLE="${INAZ_ROLE:-validator}"     # validator | replica
DATA_DIR="/var/lib/inazuma"
CONF_DIR="/etc/inazuma"
SRC_DIR="${INAZ_SRC:-$HOME/inazuma-core}"

c()  { printf '\033[38;5;205m%s\033[0m\n' "$*"; }   # magenta
ok() { printf '  \033[38;5;205m✓\033[0m %s\n' "$*"; }
die(){ printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
step(){ printf '\n'; c "── $* ────────────────────────────────────────"; }

[ "$(id -u)" = 0 ] || SUDO=sudo
SUDO="${SUDO:-}"
command -v apt-get >/dev/null || die "This installer targets Debian/Ubuntu. Follow docs/validator.md for other systems."

c ""
c "  INAZUMA VALIDATOR INSTALLER"
c "  role=$ROLE  seed=$SEED"
c ""

# ---------------------------------------------------------------- 1. machine
step "1/7  Checking this machine"
CPUS=$(nproc)
RAM_GB=$(( $(awk '/MemTotal/{print $2}' /proc/meminfo) / 1024 / 1024 ))
DISK_GB=$(df -BG --output=avail / | tail -1 | tr -dc '0-9')
echo "  cpu ${CPUS} cores · ram ${RAM_GB} GB · free disk ${DISK_GB} GB"
[ "$CPUS"   -ge 2  ] || echo "  ! 2 cores is the minimum — you have $CPUS. Expect missed slots."
[ "$RAM_GB" -ge 3  ] || echo "  ! 4 GB RAM is the minimum — you have ${RAM_GB} GB."
[ "$DISK_GB" -ge 40 ] || die "Need at least 50 GB of disk. Free some space and re-run."
ok "machine looks usable"

# ------------------------------------------------------------ 2. build deps
step "2/7  Installing build tools and Rust"
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq build-essential curl git pkg-config >/dev/null
if ! command -v cargo >/dev/null; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
fi
# shellcheck disable=SC1091
. "$HOME/.cargo/env"
ok "rust $(rustc --version | awk '{print $2}')"

# ----------------------------------------------------------------- 3. build
step "3/7  Building the node (5-10 min on 2 cores)"
if [ -d "$SRC_DIR/.git" ]; then git -C "$SRC_DIR" pull --ff-only -q; else git clone -q "$REPO_URL" "$SRC_DIR"; fi
( cd "$SRC_DIR" && cargo build --release -q )
$SUDO install -m755 "$SRC_DIR/target/release/inazuma" /usr/local/bin/inazuma
ok "installed $(inazuma --version 2>/dev/null || echo inazuma)"

# ------------------------------------------------------------------- 4. key
step "4/7  Validator key"
$SUDO mkdir -p "$CONF_DIR" "$DATA_DIR"
if [ "$ROLE" = replica ]; then
  ok "replica mode — no key needed"
  ADDRESS="(replica)"
elif $SUDO test -f "$CONF_DIR/validator.env"; then
  ok "reusing the existing key in $CONF_DIR/validator.env"
  ADDRESS=$($SUDO grep -m1 '^INAZ_ADDRESS=' "$CONF_DIR/validator.env" | cut -d= -f2- || echo unknown)
else
  KEYOUT=$(inazuma keygen)
  SECRET=$(echo "$KEYOUT" | grep -oiE '[0-9a-f]{64}' | head -1)
  ADDRESS=$(echo "$KEYOUT" | grep -oE '[1-9A-HJ-NP-Za-km-z]{32,48}' | head -1)
  [ -n "$SECRET" ] || die "keygen produced no secret — run 'inazuma keygen' manually"
  printf 'INAZ_KEY=%s\nINAZ_ADDRESS=%s\n' "$SECRET" "$ADDRESS" | $SUDO tee "$CONF_DIR/validator.env" >/dev/null
  $SUDO chmod 600 "$CONF_DIR/validator.env"
  ok "new key written to $CONF_DIR/validator.env (mode 600)"
fi

# --------------------------------------------------------------- 5. genesis
step "5/7  Genesis and data directory"
$SUDO cp "$SRC_DIR/genesis.json" "$CONF_DIR/genesis.json"
$SUDO inazuma init --data "$DATA_DIR" --genesis "$CONF_DIR/genesis.json" >/dev/null 2>&1 || true
ok "state initialised in $DATA_DIR"

# --------------------------------------------------------------- 6. systemd
step "6/7  Firewall and service"
if command -v ufw >/dev/null; then $SUDO ufw allow 9944/tcp >/dev/null 2>&1 || true; fi
if [ "$ROLE" = replica ]; then
  EXEC="/usr/local/bin/inazuma run --data $DATA_DIR --genesis $CONF_DIR/genesis.json --replica --peers $SEED --rpc 0.0.0.0:9933 --ws 0.0.0.0:9955"
  ENVLINE=""
else
  EXEC="/usr/local/bin/inazuma run --data $DATA_DIR --genesis $CONF_DIR/genesis.json --key \${INAZ_KEY} --peers $SEED --rpc 127.0.0.1:9933"
  ENVLINE="EnvironmentFile=$CONF_DIR/validator.env"
fi
$SUDO tee /etc/systemd/system/inazuma.service >/dev/null <<UNIT
[Unit]
Description=Inazuma Core node ($ROLE)
After=network-online.target

[Service]
ExecStart=$EXEC
$ENVLINE
Restart=always
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT
$SUDO systemctl daemon-reload
$SUDO systemctl enable --now inazuma
sleep 3
$SUDO systemctl is-active --quiet inazuma || die "service failed to start — run: journalctl -u inazuma -n 50"
ok "inazuma.service is running and will restart on reboot"

# ----------------------------------------------------------------- 7. done
step "7/7  Done"
cat <<DONE

  Address        $ADDRESS
  Service        systemctl status inazuma
  Live log       journalctl -u inazuma -f
  Sync progress  inazuma status

  NEXT: wait until 'inazuma status' says you are in sync (usually a few minutes),
  fund the address above with at least 1,000 INAZ, then bond:

      source $CONF_DIR/validator.env && inazuma stake --key \$INAZ_KEY --amount 1000
      inazuma validators

  BACK UP $CONF_DIR/validator.env NOW, offline. It is the only copy of your key.
  Never run the same key on a second machine — that is slashable.

DONE
