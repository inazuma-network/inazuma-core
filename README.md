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

## Start here

| I want to… | Go to |
| --- | --- |
| **Run a validator** (no prior experience needed) | [inazuma-validator](https://github.com/inazuma-network/inazuma-validator) |
| Run a node in one command | [`install-validator.sh`](https://github.com/inazuma-network/inazuma-validator/blob/main/scripts/install-validator.sh) |
| Build an app against the chain | [docs/rpc.md](docs/rpc.md) |
| Understand how it works internally | [docs/architecture.md](docs/architecture.md) |
| Report a vulnerability | [SECURITY.md](SECURITY.md) |
| Contribute code | [CONTRIBUTING.md](CONTRIBUTING.md) |

## Ecosystem repositories

This repo is the node. Everything else lives next to it:

| Repo | What it is | Use it when |
| --- | --- | --- |
| **inazuma-core** (here) | The Rust L1: consensus, state, staking, P2P, JSON-RPC, WASM VM | You run a validator or RPC node, or you want the internals |
| [inazuma-sdk](https://github.com/inazuma-network/inazuma-sdk) | TypeScript SDK: RPC client, keys, signing, sign-in, state proofs | You are building an app, bot or service |
| [inazuma-wallet](https://github.com/inazuma-network/inazuma-wallet) | Chrome/Brave/Edge extension + the `window.inazuma` provider | You hold INAZ, or your site needs wallet connect |
| [inazuma-docs](https://github.com/inazuma-network/inazuma-docs) | All written guides: introduction, wallet, staking, building, glossary, FAQ | You want to learn the network in plain English |
| [inazuma-faucet](https://github.com/inazuma-network/inazuma-faucet) | Faucet service handing out test INAZ, with rate limits | You need test INAZ, or want to run a faucet |
| [inazuma-contracts](https://github.com/inazuma-network/inazuma-contracts) | WASM contract examples, host ABI, deploy scripts | You are writing smart contracts |
| [inazuma-improvement-proposals](https://github.com/inazuma-network/inazuma-improvement-proposals) | INAZIPs — written proposals for protocol changes, and the process they follow | You want to change how the chain works |

Project standards live in every repo: [CONTRIBUTING.md](CONTRIBUTING.md),
[SECURITY.md](SECURITY.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md),
[SUPPORT.md](SUPPORT.md), [GOVERNANCE.md](GOVERNANCE.md), [ROADMAP.md](ROADMAP.md)
and [CHANGELOG.md](CHANGELOG.md).

## Run a node in one command

Ubuntu 22.04 / Debian 12, 2 vCPU, 4 GB RAM, 50 GB NVMe. The script installs Rust,
builds the node, creates your key, initialises from genesis and installs a systemd
service that survives reboots:

```bash
curl -sSf https://raw.githubusercontent.com/inazuma-network/inazuma-validator/main/scripts/install-validator.sh | bash
```

Read-only node instead: `INAZ_ROLE=replica bash install-validator.sh`.
Re-running upgrades the binary and never touches your key or data.

## Documentation

| Guide | What's in it |
| --- | --- |
| [inazuma-validator](https://github.com/inazuma-network/inazuma-validator) | **Run a validator** — server sizing, one-command install, manual install, staking, monitoring, hardening, slashing, troubleshooting, FAQ |
| [docs/rpc.md](docs/rpc.md) | JSON-RPC methods, WebSocket subscriptions, state proofs, rate limits |
| [docs/architecture.md](docs/architecture.md) | Module map, consensus, native tokens, key format and quantum posture |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure and operator hardening |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Build, test, and the activation-height rule for consensus changes |

## Quick start (manual build)

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
recovery from jail — is in **[inazuma-validator](https://github.com/inazuma-network/inazuma-validator)**.

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
docs/           RPC reference, architecture
```

## Status

Live network with a 3-validator set. Slashing enforcement is active from block 130,000
and sparse-Merkle state proofs from block 200,000. Roadmap: broader validator set,
historical transaction indexer, trustless bridge on top of state proofs.

## License

MIT — see [LICENSE](LICENSE).

---

## Why Inazuma exists

Inazuma is a sovereign layer 1 — our own consensus, state machine, networking and VM, not
a rollup or a fork. The goal is narrow and deliberate: **be the home chain for memes,
NFTs, collectibles, games and communities.**

That use case is high volume and low value per transaction. A 500-piece mint, a game
writing a move a second, a community handing out collectibles — none of them can pay
dollars in fees or wait seconds for a confirmation. So the whole design is bent around
being fast and near-free:

| | |
| --- | --- |
| Block time | 400 ms, finalised in the same block |
| Transfer fee | ~0.000001 INAZ — fractions of a cent |
| Throughput | ~2,500 tx/s ingest; 20k-36k tx/s execution in bench |
| Tokens & NFTs | first-class chain records — no contract needed to mint |
| Contracts | gas-metered WASM |
| Accounts | Ed25519, base58 addresses, optional ML-DSA-65 co-signature |
| Light clients | sparse Merkle state proofs |

Getting to top-tier means three things, in this order: enough independent validators that
nobody can stop the chain, tooling good enough that a first-time builder ships in an
afternoon, and fees that stay boring even when a collection goes viral. Every repo below
is one part of that.

## The Inazuma repos

| Repo | What's in it |
| --- | --- |
| **inazuma-core** (here) | The Rust L1: consensus, state, staking, P2P, JSON-RPC, WASM VM |
| [inazuma-validator](https://github.com/inazuma-network/inazuma-validator) | Node operators: one-command installer, systemd units, health checks, full guide |
| [inazuma-sdk](https://github.com/inazuma-network/inazuma-sdk) | TypeScript client: RPC, keys, signing, sign-in, state proofs |
| [inazuma-wallet](https://github.com/inazuma-network/inazuma-wallet) | Self-custody wallet: browser extension, web and Android |
| [inazuma-contracts](https://github.com/inazuma-network/inazuma-contracts) | WASM contract examples, host ABI and deploy scripts |
| [inazuma-faucet](https://github.com/inazuma-network/inazuma-faucet) | Test-token faucet service |
| [inazuma-docs](https://github.com/inazuma-network/inazuma-docs) | All written guides, organised by role |
| [inazuma-improvement-proposals](https://github.com/inazuma-network/inazuma-improvement-proposals) | INAZIPs — how the chain changes |

## Getting started, whoever you are

| I want to… | Go to |
| --- | --- |
| Use a wallet and send INAZ | [inazuma-wallet](https://github.com/inazuma-network/inazuma-wallet) |
| Get test INAZ | [inazuma-faucet](https://github.com/inazuma-network/inazuma-faucet) |
| Build an app | [inazuma-sdk](https://github.com/inazuma-network/inazuma-sdk) · [inazuma-contracts](https://github.com/inazuma-network/inazuma-contracts) |
| Run a node or stake | [inazuma-validator](https://github.com/inazuma-network/inazuma-validator) |
| Understand the internals | [inazuma-core](https://github.com/inazuma-network/inazuma-core) |
| Propose a protocol change | [INAZIPs](https://github.com/inazuma-network/inazuma-improvement-proposals) |
