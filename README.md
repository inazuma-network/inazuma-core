<h1 align="center">Inazuma Core</h1>

<p align="center">
  A sovereign layer-1 blockchain written from scratch in Rust.<br/>
  400 ms blocks · Ed25519 accounts · native tokens · WASM contracts · proof-carrying state.
</p>

<p align="center">
  <a href="https://github.com/inazuma-network/inazuma-core/actions/workflows/ci.yml"><img alt="ci" src="https://github.com/inazuma-network/inazuma-core/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="rust" src="https://img.shields.io/badge/rust-1.80%2B-000000">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-000000">
</p>

---

No Geth, no Cosmos SDK, no subnet framework. Our own block format, state machine,
consensus loop, networking stack and JSON-RPC. **INAZ** is the native coin and the
staking coin — nobody needs to hold another chain's token to validate.

| | |
| --- | --- |
| Chain ID | `7777` |
| Coin | `INAZ`, 9 decimals (smallest unit `rai`) |
| Block time | 400 ms, up to 5,000 tx per block |
| Consensus | stake-weighted deterministic leader election + precommit finality |
| Accounts | Ed25519, base58 addresses, domain-separated derivation |
| Minimum fee | 1,000 rai (0.000001 INAZ) |
| Minimum stake | 1,000 INAZ · unbonding 300 blocks |
| Measured | ~2,500 tx/s sustained ingestion, 20,000–36,000 tx/s execution |

## Documentation

| Guide | What's in it |
| --- | --- |
| [docs/validator.md](docs/validator.md) | **Run a validator** — hardware, build, keys, genesis, systemd, staking, slashing, troubleshooting |
| [docs/rpc.md](docs/rpc.md) | JSON-RPC methods, WebSocket subscriptions, state proofs, rate limits |
| [docs/architecture.md](docs/architecture.md) | Module map, consensus, native tokens, key format and quantum posture |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure and operator hardening |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Build, test, and the activation-height rule for consensus changes |

## Quick start

```bash
git clone https://github.com/inazuma-network/inazuma-core.git
cd inazuma-core
cargo build --release
sudo install -m755 target/release/inazuma /usr/local/bin/inazuma

inazuma keygen                                     # your account + validator identity
inazuma init --data ./data --genesis ./genesis.json
inazuma run  --data ./data --genesis ./genesis.json \
  --key <SECRET_HEX> --rpc 127.0.0.1:9933
```

Join the public network by adding `--peers rpc.inazuma.network:9944`, wait until
`inaz_nodeStatus` reports you in sync, then bond:

```bash
inazuma stake --key <SECRET_HEX> --amount 1000
inazuma validators
```

Full walkthrough — firewall rules, encrypted P2P pinning, systemd unit, monitoring and
recovery from jail — is in **[docs/validator.md](docs/validator.md)**.

## CLI

```bash
inazuma send    --key <SECRET> --to <ADDRESS> --amount 12.5
inazuma stake   --key <SECRET> --amount 1000
inazuma unstake --key <SECRET> --amount 1000
inazuma balance --address <ADDRESS>
inazuma validators                        # active set, stake shares, next leader
inazuma status                            # height, sync state, missed-slot streak
inazuma slashing                          # params, jail state, slash history
inazuma report   --evidence ./evidence.json
inazuma unjail  --key <SECRET>
inazuma bench   --key <SECRET> --count 1000
```

## Node roles

- **Validator** — produces blocks, votes, earns fees and rewards. Needs a key and stake.
- **Read replica** — `--replica` syncs and serves reads, never produces or votes. No key,
  no stake, scale horizontally behind a load balancer.
- **Archive / RPC provider** — a replica with `--ws` for push subscriptions and
  `--rpc-stake-keys` to sell stake-weighted priority.

## Layout

```
src/            node: crypto, state, consensus, staking, slashing, p2p, rpc, ws, vm
contracts/      example WASM contract source
genesis.json    genesis allocation and chain parameters
docs/           validator guide, RPC reference, architecture
```

## Status

Live network with a 3-validator set. Slashing enforcement is active from block 130,000
and sparse-Merkle state proofs from block 200,000. Roadmap: broader validator set,
historical transaction indexer, trustless bridge on top of state proofs.

## License

MIT — see [LICENSE](LICENSE).
