# Inazuma Core

A blockchain written from scratch in Rust. No Avalanche, no Cosmos, no Geth — our own
block format, state machine, consensus loop, and JSON-RPC. **INAZ** is the native coin
and the staking coin. Nobody needs to hold another chain's token to validate.

- Chain ID: `7777`
- Symbol: `INAZ`, 9 decimals (smallest unit: `rai`, 1 INAZ = 1_000_000_000 rai)
- Block time: 400 ms
- Signatures: Ed25519
- Addresses: `inz` + 20-byte hash of the public key
- Minimum fee: 1_000 rai (0.000001 INAZ)
- Block reward: 0.01 INAZ per block, shared by the validator set
- Staking coin: **INAZ itself** - 1,000 INAZ minimum stake, no other chain's token needed

## Layout

```
src/crypto.rs   keys, addresses, signing, hashing
src/types.rs    accounts, transactions, blocks, merkle root, genesis
src/state.rs    embedded KV store: accounts, blocks, tx index, state root
src/chain.rs    mempool, transaction execution, block production
src/staking.rs  validator set, stake-weighted leader election, rewards, unbonding
src/rpc.rs      JSON-RPC over HTTP (no web framework, raw sockets)
src/main.rs     node binary + CLI
```

## Build

```bash
cargo build --release
# binary: target/release/inazuma
```

## Run a node

```bash
# 1. create the chain owner key
inazuma keygen

# 2. seal genesis (1,000,000 INAZ to the admin address)
inazuma init --data ./data --genesis ./genesis.json --admin inz<address> --key <secret>

# 3. run it
inazuma run --data ./data --genesis ./genesis.json --key <secret> --rpc 0.0.0.0:9933
```

The node produces a block every 400 ms and serves JSON-RPC on `--rpc`.
`INAZUMA_KEY` works instead of `--key`. With no key at all, a node key is generated
next to the data directory.

## CLI

```bash
inazuma send    --key <secret> --to inz<addr> --amount 12.5
inazuma stake   --key <secret> --amount 1000
inazuma unstake --key <secret> --amount 1000
inazuma balance --address inz<addr>
inazuma validators                              # active set, stake shares, next leader
inazuma bench   --key <secret> --count 1000     # throughput check
```

## JSON-RPC

POST JSON-RPC 2.0 to the node. CORS is open so the website can call it directly.

| Method | Params | Returns |
| --- | --- | --- |
| `inaz_chainInfo` | — | chain id, height, supply, staked, mempool, producer |
| `inaz_blockNumber` | — | tip height |
| `inaz_getAccount` / `inaz_getBalance` | `{ address }` | balance, staked, nonce, pendingNonce |
| `inaz_getBlockByNumber` | `{ height }` | block with transactions |
| `inaz_latestBlocks` | `{ limit }` | newest blocks first |
| `inaz_validators` | - | active set, stake shares, rewards, next leader |
| `inaz_getTransaction` | `{ hash }` | transaction + block reference |
| `inaz_sendTransaction` | `{ tx }` | `{ hash, status }` |

`GET /health` returns `{ ok, height }`. All amounts are returned as strings so
JavaScript never loses precision.

## Transaction format

Signed over canonical bytes (no JSON ambiguity):

```
inazuma-tx|<chainId>|<kind>|<fromPubkey>|<to>|<amount>|<fee>|<nonce>
```

`kind` is `transfer`, `stake`, or `unstake`.

## Measured locally

- 400 ms blocks, up to 5,000 transactions per block
- 400/400 transactions accepted and confirmed with zero rejections
- ~1,080 tx/s submit rate through a single-threaded CLI client; block execution
  absorbed 269 transactions in one 400 ms block without falling behind

## Proof of stake

Stake is denominated in INAZ, the same coin that pays gas. There is no external
staking asset.

- **Become a validator:** `stake` at least 1,000 INAZ. The account enters the active
  set on the next block.
- **Leader election:** for every height each node computes
  `sha256("inazuma-leader|height|parentHash")` and draws a leader weighted by stake.
  Deterministic, so all nodes agree on whose slot it is without talking.
- **Rewards:** the leader takes all fees in its block plus a 20% commission on the
  block reward. The other 80% is split across the active set in proportion to stake
  and credited immediately.
- **Unbonding:** `unstake` removes stake right away but locks the coins for 300 blocks
  (~2 minutes at 400 ms). The chain releases them into the spendable balance
  automatically at the release height - no claim transaction.
- **Bootstrap:** with no stake on chain yet, the running node keeps the reward so the
  chain can start from nothing.
- Single-node mode (default today): one node seals every slot even when another
  validator is elected, so the devnet never stalls. Switched off once nodes gossip
  blocks in Stage 3.

Verified on a fresh chain: two validators at 5,000 / 2,000 INAZ received 71.42% /
28.57% of rewards, leadership rotated between them, and an unstake of 2,000 INAZ was
locked then credited back automatically at the release height.

## Status

**Stage 1 complete:** keys, transactions, state, block production, JSON-RPC, CLI.
**Stage 2 complete:** INAZ proof of stake - validator set, stake-weighted leader
election, proportional rewards, unbonding period.

Next: P2P gossip with BFT finality across multiple nodes, WASM smart contracts, then
indexer + native explorer and wallet on the website.

## Stage 4 - native tokens

Tokens are part of the state machine, not a smart contract. That means a meme coin
or a game currency on Inazuma costs one transaction, executes in the same 400 ms
block as a plain transfer, and cannot be broken by contract bugs.

- **Create:** `token-create --symbol RAIJIN --name "Raijin Meme" --supply 1000000
  --decimals 9 [--mintable true]`. Costs a 10 INAZ creation fee that goes to the
  validator set, so spam is expensive and validators are paid for the state.
- **Token id:** deterministic - `sha256(creator | nonce | symbol)` - so every node
  derives the same id, and the CLI can print it before the block is even sealed.
- **Mint / burn:** only the creator can mint, and only while `mintable` is true.
  A fixed-supply token can never be inflated. Anyone can burn what they hold.
- **Transfer:** `token-send --token ID --to ADDR --amount N`. Fees are always paid
  in INAZ, so INAZ stays the only gas and staking coin.
- **Consensus state:** the token registry and every token balance are hashed into
  the state root, so a peer that disagrees about one token balance is rejected.

New RPC: `inaz_tokens`, `inaz_getToken` (with top holders), `inaz_tokenBalance`,
`inaz_tokenHoldings`.

Verified live on a fresh chain: created RAIJIN with 1,000,000 supply, transferred
12,345.5 to a second account, minted 500, burned 1,000. Final supply 999,500 across
2 holders with balances matching exactly, and the 10 INAZ creation fee paid out to
the validator.

## Slashing & jailing

Enforcement activates at block **130,000** so all earlier history replays
unchanged.

| Offence | Detection | Penalty |
| --- | --- | --- |
| Equivocation (two blocks or two precommits at one height) | `slashing::Evidence` verified against the offender's own signatures | Burn `max(5%, 3 x stake share)` of stake, permanent tombstone |
| Downtime | 50 consecutive missed leader slots | Jail for 10,000 blocks; repeat offences burn 0.1% |

Reporting is permissionless and pays **10%** of the burn to the reporter.
Evidence stays valid for 100,000 blocks; unbonding takes 300 blocks so stake
cannot escape a pending report.

```bash
inazuma slashing                          # params, jail state, slash history
inazuma report --evidence ./evidence.json # submit a proof, collect the bounty
inazuma unjail --key <SECRET_HEX>         # rejoin after a downtime jail
```

RPC: `inaz_slashing`, `inaz_previewSlash`, `inaz_reportEquivocation`.
Honest nodes detect and gossip evidence automatically — no operator action needed.
