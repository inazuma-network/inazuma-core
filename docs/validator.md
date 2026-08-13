# Run an Inazuma validator

**Time needed:** ~20 minutes, most of it waiting for a compile.
**Skills needed:** you can rent a server and paste commands into a terminal. That's it.

Everything below has been run end to end on a fresh Ubuntu 22.04 box.

---

## What a validator actually is

Inazuma produces a block every 400 ms. Someone has to build each of those blocks,
and everyone else has to agree it is valid. A **validator** is a small server that:

1. keeps a full copy of the chain,
2. gets picked in turn to produce a block (more stake = picked more often),
3. votes on the blocks other validators produce,
4. earns the fees and block rewards for the blocks it produces.

To be picked, you lock up ("bond") **1,000 INAZ**. If you cheat, part of that stake is
burned. If you go offline, you are temporarily benched. That is the whole deal.

There is no allowlist, no application form, no whitelist. Bond and you're in on the
next block.

| Term | Plain English |
| --- | --- |
| **Stake / bond** | INAZ you lock so the network can punish you if you misbehave |
| **Slot** | Your turn to produce a block |
| **Missed slot** | Your turn came and your node didn't produce — usually offline or behind |
| **Jailed** | Benched for a while after too many missed slots. No stake burned. |
| **Slashed** | Stake burned for provable cheating (signing two blocks at one height) |
| **Tombstoned** | That key is banned forever. Only happens for double-signing. |
| **Unbonding** | The 300-block wait before withdrawn stake becomes spendable |
| **Replica** | A node that syncs and answers queries but does not validate. No stake needed. |
| **Genesis** | The chain's block 0. Every node must use the identical file. |

---

## 1. Pick a server

You do **not** need a powerful machine. You need a *consistent* one on a *fast disk*.
400 ms blocks mean a slow disk hurts you far more than a slow CPU.

| Setup | vCPU | RAM | Disk | Good for |
| --- | --- | --- | --- | --- |
| **Minimum** | 2 | 4 GB | 50 GB NVMe | works, but little headroom |
| **Recommended** | 4 | 8 GB | 100 GB NVMe | what we run in production |
| **Heavy RPC / replica** | 8 | 16 GB | 200 GB NVMe | if you also serve public traffic |

Also required:

- **Ubuntu 22.04 or Debian 12**, 64-bit, root or sudo access
- **Static public IP** and inbound **TCP 9944** open
- **Unmetered or ≥ 2 TB/month bandwidth** (gossip is constant)
- **NVMe SSD.** Not HDD, not network storage, not "cloud volume". Local NVMe.

Rules of thumb we've learned the hard way:

- 1 vCPU works only for a replica, never a validator.
- Shared/burstable CPU plans (the very cheap tier at most hosts) throttle at exactly
  the wrong moment and cause missed-slot streaks. Pay for dedicated cores.
- Put your validator and your backup in **different data centres**. Two boxes in one
  rack fail together.
- Budget: a suitable VPS is roughly **$10-25/month** at most providers.

> Any provider works — a rented VPS, a dedicated box, a machine at home behind a
> port-forward, or your own rack. The node has no cloud dependencies at all.

---

## 2. Install — the easy way (one command)

This installs dependencies, builds the node, creates your key, initialises from
genesis, sets up a systemd service and starts it:

```bash
curl -sSf https://raw.githubusercontent.com/inazuma-network/inazuma-core/main/scripts/install-validator.sh | bash
```

Prefer to read it first (you should):

```bash
curl -sSfO https://raw.githubusercontent.com/inazuma-network/inazuma-core/main/scripts/install-validator.sh
less install-validator.sh
bash install-validator.sh
```

Options, passed as environment variables:

```bash
INAZ_ROLE=replica  bash install-validator.sh      # read-only node, no key, no stake
INAZ_PEERS=1.2.3.4:9944 bash install-validator.sh # join via a different seed
```

The installer is **idempotent** — re-run it any time to upgrade the binary. It never
overwrites an existing key or data directory.

When it finishes it prints your address. Skip to [step 4](#4-bond-your-stake).

---

## 3. Install — the manual way

Do this if you want to understand every moving part, or you're not on Debian/Ubuntu.

### 3.1 Prepare the machine

```bash
sudo apt update && sudo apt install -y build-essential curl git pkg-config
curl https://sh.rustup.rs -sSf | sh -s -- -y && . "$HOME/.cargo/env"

sudo ufw allow 9944/tcp      # P2P must be reachable
sudo ufw enable              # RPC stays private for now
```

### 3.2 Build the node

Rust 1.80+ is the only prerequisite. One binary; no framework, no external VM.

```bash
git clone https://github.com/inazuma-network/inazuma-core.git
cd inazuma-core
cargo build --release
sudo install -m755 target/release/inazuma /usr/local/bin/inazuma
inazuma --version
```

### 3.3 Create your validator key

```bash
inazuma keygen | tee ~/validator.txt
chmod 600 ~/validator.txt
```

The base58 address printed is both your account and your validator identity.

> **Back the secret up offline, right now.** Lose it and you can neither sign blocks
> nor ever withdraw your stake. No one can recover it for you.
>
> **Never run one key on two machines.** Two nodes signing at the same height is
> indistinguishable from an attack and is tombstoned permanently.

### 3.4 Initialise from genesis

Use the network's `genesis.json`, byte for byte. A different file means a different
state root on block 1 and every peer will reject you.

```bash
sudo mkdir -p /etc/inazuma /var/lib/inazuma
sudo cp genesis.json /etc/inazuma/genesis.json
inazuma init --data /var/lib/inazuma --genesis /etc/inazuma/genesis.json
```

### 3.5 Sync before you stake

A validator elected while still syncing misses slots and gets jailed. Start unbonded,
let it catch up, *then* bond.

```bash
inazuma run --data /var/lib/inazuma --genesis /etc/inazuma/genesis.json \
  --key <SECRET_HEX> \
  --peers rpc.inazuma.network:9944 \
  --rpc 127.0.0.1:9933

# in another shell — are we caught up?
inazuma status
```

`INAZ_KEY` in the environment works instead of `--key`, so the secret never lands in
your shell history.

### 3.6 Run it under systemd

Downtime is punished, so never leave the node running in an SSH session.

```bash
sudo tee /etc/inazuma/validator.env >/dev/null <<'EOF2'
INAZ_KEY=<SECRET_HEX>
EOF2
sudo chmod 600 /etc/inazuma/validator.env

sudo tee /etc/systemd/system/inazuma.service >/dev/null <<'EOF2'
[Unit]
Description=Inazuma Core validator
After=network-online.target

[Service]
ExecStart=/usr/local/bin/inazuma run --data /var/lib/inazuma \
  --genesis /etc/inazuma/genesis.json \
  --key ${INAZ_KEY} --peers rpc.inazuma.network:9944 --rpc 127.0.0.1:9933
EnvironmentFile=/etc/inazuma/validator.env
Restart=always
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF2

sudo systemctl daemon-reload && sudo systemctl enable --now inazuma
journalctl -u inazuma -f
```

---

## 4. Bond your stake

Fund your address with at least 1,000 INAZ, confirm you're synced, then:

```bash
inazuma status                                  # must say in sync
inazuma stake --key <SECRET_HEX> --amount 1000
inazuma validators                              # you should be in the active set
```

You are now in the leader rotation. Rewards: the leader keeps every fee in its block
plus 20% commission on the block reward; the remaining 80% is split across the active
set in proportion to stake and credited immediately — there is no claim transaction.

---

## 5. Day-to-day operation

```bash
inazuma status         # height, sync state, missed-slot streak
inazuma validators     # active set, stake shares, next leader
inazuma slashing       # params, jail state, slash history
inazuma unstake --key <SECRET_HEX> --amount 1000
inazuma unjail  --key <SECRET_HEX>
```

Watch exactly three things. Everything else is noise:

1. **missed-slot streak** — should stay at 0-2
2. **lag versus the network tip** — should be under a couple of blocks
3. **free disk** — top up long before it fills

### A 60-second health check you can cron

```bash
inazuma status | grep -Ei 'height|sync|missed'
systemctl is-active inazuma
df -h /var/lib/inazuma | tail -1
```

### Upgrading

```bash
cd ~/inazuma-core && git pull && cargo build --release
sudo install -m755 target/release/inazuma /usr/local/bin/inazuma
sudo systemctl restart inazuma
```

Consensus changes always ship behind an activation height, so upgrading early is safe
and upgrading late is what breaks you. Watch releases.

---

## 6. Hardening (do this once you're stable)

### Encrypted, pinned P2P

Every peer connection is an INSC1 session: ephemeral X25519 exchange, an Ed25519
signature over the handshake transcript, then ChaCha20-Poly1305 framing. Pin the node
keys you accept so an attacker can't surround you with fake peers (eclipse attack).

```bash
inazuma run ... \
  --peers rpc.inazuma.network:9944 \
  --peer-ids <PEER_NODE_KEY_HEX>,<PEER_NODE_KEY_HEX> \
  --require-encrypted-p2p

curl -s localhost:9933 -d '{"jsonrpc":"2.0","id":1,"method":"inaz_netInfo"}'
```

### Keep RPC private

Bind RPC to `127.0.0.1` unless you intend to serve the public. If you do serve it, see
[docs/rpc.md](rpc.md) for API keys, per-method cost weighting and stake-weighted rate
limits.

### Basic server hygiene

```bash
sudo apt install -y unattended-upgrades fail2ban
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

Keep your key file at mode 600, owned by root, and never in a git repo, a screenshot,
a support chat or a cloud sync folder.

---

## 7. Slashing & jailing — exactly what gets punished

Enforcement activates at block **130,000**, so all earlier history replays unchanged.

| Offence | How it's detected | Penalty |
| --- | --- | --- |
| **Equivocation** — two blocks or two precommits at one height | evidence verified against your own signatures | burn `max(5%, 3 × stake share)`, **permanent tombstone** |
| **Downtime** — 50 consecutive missed leader slots | counted on chain | jailed 10,000 blocks (~1 h), no burn; repeat offences burn 0.1% |
| **Invalid block / bad state root** | peers reject it; it never finalises | no burn, slot counted as missed |

A worked example: a validator holding 20% of total stake double-signs. `3 × 20% = 60%`,
which is larger than the 5% floor, so **60% of its stake is burned** and the key is
banned forever. A validator with 1% of stake loses the 5% floor instead. The bigger you
are, the more an attack costs you — that's deliberate.

Reporting is permissionless and pays the reporter **10% of the burn**. Evidence stays
valid for 100,000 blocks, and unbonding takes 300 blocks, so stake cannot outrun a
pending report.

```bash
inazuma report --evidence ./evidence.json
```

**Downtime never burns stake on a first offence.** The realistic worst case for an
honest operator is a lost hour of rewards. The only way to lose real money is running
one key twice — so don't.

---

## 8. Read replicas (no stake required)

Reads and consensus are different jobs. A replica syncs every block but never produces
one and never votes, so you can put as many behind a load balancer as traffic needs
without touching the validator set.

```bash
inazuma run --data /var/lib/inazuma-replica --genesis /etc/inazuma/genesis.json \
  --replica --peers rpc.inazuma.network:9944 \
  --rpc 0.0.0.0:9933 --ws 0.0.0.0:9955
```

Or with the installer: `INAZ_ROLE=replica bash install-validator.sh`.

---

## 9. Troubleshooting

| What you see | Why | Fix |
| --- | --- | --- |
| `state root mismatch` at a low height | wrong `genesis.json` | re-`init` with the network genesis into a **clean** data dir |
| no peers after 60 s | 9944 closed, or wrong `--peers` | `sudo ufw allow 9944/tcp`, check the seed address |
| missed-slot streak keeps growing | node behind, or disk too slow | check lag with `inazuma status`; move to local NVMe |
| jailed | 50 missed slots in a row | fix the node, wait out the jail height, then `inazuma unjail` |
| `nonce too low` when sending | stale pending nonce | read `pendingNonce` from `inaz_getAccount` |
| service dies on boot | `EnvironmentFile` missing or unreadable | `sudo chmod 600 /etc/inazuma/validator.env`, `daemon-reload` |
| `cargo: command not found` after reconnecting | Rust env not sourced | `. "$HOME/.cargo/env"` (or re-login) |
| build killed on a 2 GB box | out of memory during link | add 2 GB swap, or build on a bigger box and copy the binary |

Still stuck? Open a [Validator support issue](https://github.com/inazuma-network/inazuma-core/issues/new/choose)
with the output of `inazuma status` and the last 50 lines of `journalctl -u inazuma`.

---

## 10. FAQ

**Do I need to know Rust?** No. You need to paste about eight commands.

**Can I run it at home?** Yes, if you can forward TCP 9944 and your connection is
stable. A residential outage costs you rewards, not stake.

**Can I run two validators?** Yes — two machines, **two different keys**. Never the
same key twice.

**What if I lose my key?** The stake is gone. Back up `validator.env` offline before
you bond anything.

**Can I unstake whenever I want?** Yes; it becomes spendable after 300 blocks (~2 min).

**Is my stake at risk if I'm just offline?** No burn on a first downtime offence — you
get benched and lose that period's rewards.

**Do I need a domain or TLS?** Only if you serve public RPC. A validator needs neither.

**How much does it cost to run?** A suitable VPS is roughly $10-25/month.

---

## Where to go next

- [docs/rpc.md](rpc.md) — JSON-RPC, WebSocket subscriptions, state proofs, rate limits
- [docs/architecture.md](architecture.md) — consensus, state, key format, quantum posture
- [SECURITY.md](../SECURITY.md) — disclosure policy and operator hardening
