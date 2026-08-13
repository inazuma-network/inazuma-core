# Running an Inazuma validator

Every validator runs the same binary as every other node. There is no permissioned
set, no allowlist and no external staking asset: bond 1,000 INAZ and you are in the
leader rotation on the next block.

- Chain ID `7777` · block time 400 ms · Ed25519 keys · base58 addresses
- Minimum stake **1,000 INAZ** · unbonding **300 blocks** (~2 min)
- P2P `9944/tcp` · JSON-RPC `9933` · WebSocket `9955`

## 0. Hardware

| Role | vCPU | RAM | Disk | Notes |
| --- | --- | --- | --- | --- |
| Validator (minimum) | 2 | 4 GB | 50 GB NVMe | 400 ms slots — disk latency matters more than clock speed |
| Validator (recommended) | 4 | 8 GB | 100 GB NVMe | headroom for mempool bursts and evidence gossip |
| Read replica | 2 | 4 GB | 50 GB NVMe | no key, no stake, serves reads only |

Spinning disks and network-attached storage will make you miss slots. Use local NVMe.

## 1. Prepare the machine

```bash
sudo apt update && sudo apt install -y build-essential curl git pkg-config
curl https://sh.rustup.rs -sSf | sh -s -- -y && . "$HOME/.cargo/env"

# P2P must be reachable; keep RPC private unless you intend to serve it
sudo ufw allow 9944/tcp
sudo ufw enable
```

## 2. Build

Rust 1.80+ is the only prerequisite. One binary, no framework, no external VM.

```bash
git clone https://github.com/inazuma-network/inazuma-core.git
cd inazuma-core
cargo build --release
sudo install -m755 target/release/inazuma /usr/local/bin/inazuma
inazuma --version
```

## 3. Create the validator key

```bash
inazuma keygen | tee ~/validator.txt
chmod 600 ~/validator.txt
```

The printed base58 address is both your account and your validator identity. Back the
secret up offline. Losing it means you can neither sign blocks nor unbond your stake.

> **Never run one key on two machines.** Two nodes signing at the same height is
> indistinguishable from an attack and is tombstoned permanently.

## 4. Initialise from genesis

Use the same `genesis.json` as the network, otherwise your state root will diverge on
block 1 and peers will reject you.

```bash
sudo mkdir -p /etc/inazuma /var/lib/inazuma
sudo cp genesis.json /etc/inazuma/genesis.json
inazuma init --data /var/lib/inazuma --genesis /etc/inazuma/genesis.json
```

## 5. Sync before you stake

A validator elected while still syncing misses slots and gets jailed. Start unstaked,
wait for the tip to match the network, then bond.

```bash
inazuma run --data /var/lib/inazuma --genesis /etc/inazuma/genesis.json \
  --key <SECRET_HEX> \
  --peers rpc.inazuma.network:9944 \
  --rpc 127.0.0.1:9933

# in another shell
curl -s localhost:9933 -d '{"jsonrpc":"2.0","id":1,"method":"inaz_nodeStatus"}'
```

`INAZUMA_KEY` works instead of `--key` so the secret never lands in your shell history.

## 6. Harden the P2P link

Each peer connection is an INSC1 session: ephemeral X25519 exchange, an Ed25519
signature over the handshake transcript, then ChaCha20-Poly1305 framing. Pin the node
keys you accept so an attacker cannot surround you with sybil peers (eclipse attack).

```bash
inazuma run ... \
  --peers rpc.inazuma.network:9944 \
  --peer-ids <PEER_NODE_KEY_HEX>,<PEER_NODE_KEY_HEX> \
  --require-encrypted-p2p

curl -s localhost:9933 -d '{"jsonrpc":"2.0","id":1,"method":"inaz_netInfo"}'
```

## 7. Run it under systemd

Downtime is punished, so never run the node in a shell.

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

## 8. Bond stake

```bash
inazuma stake --key <SECRET_HEX> --amount 1000
inazuma validators     # confirm you are in the active set
```

Rewards: the leader keeps every fee in its block plus 20% commission on the block
reward; the remaining 80% is split across the active set in proportion to stake and
credited immediately — no claim transaction.

## 9. Operate

```bash
inazuma status         # height, sync state, missed-slot streak
inazuma validators     # active set, stake shares, next leader
inazuma slashing       # params, jail state, slash history
inazuma unstake --key <SECRET_HEX> --amount 1000
inazuma unjail  --key <SECRET_HEX>
```

Watch three things daily: your missed-slot streak, your lag versus the network tip,
and free disk. Everything else is noise.

## 10. Read replicas (optional)

Reads and consensus are different jobs. A replica syncs every block but never produces
one and never votes, so you can put as many behind a load balancer as traffic needs
without touching the validator set. No key, no stake.

```bash
inazuma run --data /var/lib/inazuma-replica --genesis /etc/inazuma/genesis.json \
  --replica --peers rpc.inazuma.network:9944 \
  --rpc 0.0.0.0:9933 --ws 0.0.0.0:9955
```

## Slashing & jailing

Enforcement activates at block **130,000**, so all earlier history replays unchanged.

| Offence | Detection | Penalty |
| --- | --- | --- |
| Equivocation (two blocks or two precommits at one height) | evidence verified against the offender's own signatures | burn `max(5%, 3 × stake share)`, permanent tombstone |
| Downtime | 50 consecutive missed leader slots | jail 10,000 blocks; repeat offences burn 0.1% |
| Invalid block / bad state root | peers reject the block; it never finalises | no burn, slot counted as missed |

Reporting is permissionless and pays the reporter **10%** of the burn. Evidence stays
valid for 100,000 blocks, and unbonding takes 300 blocks, so stake cannot escape a
pending report.

```bash
inazuma report --evidence ./evidence.json
```

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `state root mismatch` at low height | wrong `genesis.json` | re-`init` with the network genesis into a clean data dir |
| no peers after 60 s | 9944 closed or wrong `--peers` | open the port, verify the seed address |
| growing missed-slot streak | node behind or disk too slow | check `inaz_nodeStatus` lag, move to NVMe |
| jailed | 50 missed slots in a row | fix the node, wait out the jail height, `inazuma unjail` |
| `nonce too low` when sending | stale pending nonce | read `pendingNonce` from `inaz_getAccount` |
