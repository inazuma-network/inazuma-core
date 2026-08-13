# Architecture

Inazuma Core is a single Rust binary. No Geth, no Cosmos SDK, no Avalanche subnet —
our own block format, state machine, consensus loop, networking and RPC.

```
src/crypto.rs      keys, addresses, signing, hashing (Ed25519, domain-separated)
src/types.rs       accounts, transactions, blocks, merkle root, genesis
src/state.rs       embedded KV store: accounts, blocks, tx index, state root
src/smt.rs         sparse Merkle tree (depth 128) for light-client proofs
src/chain.rs       transaction execution, batched admission, block production
src/mempool.rs     indexed pool, O(1) admission, fee-priority eviction
src/fees.rs        EIP-1559-style dynamic base fee
src/consensus.rs   precommit voting, finality, fork choice
src/staking.rs     validator set, stake-weighted leader election, rewards, unbonding
src/slashing.rs    equivocation evidence, downtime tracking, jail & tombstone
src/p2p.rs         gossip: blocks, transactions, votes, evidence
src/transport.rs   INSC1 encrypted channel (X25519 + ChaCha20-Poly1305)
src/limits.rs      connection caps, IP rate limiting, peer scoring
src/rpc.rs         JSON-RPC 2.0 over raw sockets (no web framework)
src/rpcauth.rs     tiers: anonymous / key / admin, weighted metering
src/qos.rs         stake-weighted request budgets
src/ws.rs          WebSocket subscriptions
src/events.rs      internal event bus feeding subscriptions
src/simulate.rs    transaction preflight
src/contracts.rs   WASM contract execution
src/tokens.rs      native tokens in the state machine
src/main.rs        node binary + CLI
```

## Consensus

Deterministic stake-weighted leader election: at each height every node computes
`sha256("inazuma-leader|height|parentHash")` and draws a leader weighted by stake, so
all nodes agree on whose slot it is without exchanging a message. The leader proposes,
peers precommit, and a block finalises once precommits representing more than two
thirds of stake are seen.

## Native tokens

Tokens live in the state machine, not in a contract. A token transfer costs one
transaction and executes in the same 400 ms block as a plain transfer, and cannot be
broken by contract bugs. Token ids are deterministic —
`sha256(creator | nonce | symbol)` — and the registry plus every token balance is
hashed into the state root.

## Keys and quantum posture

Addresses are base58 over an Ed25519 public key using a domain-separated derivation
path, so an Inazuma key can never collide with an EVM or another chain's address space.
Private keys export as `inazkey1`-prefixed base58check, deliberately incompatible with
other wallets' formats. Accounts may additionally carry ML-DSA-65 (post-quantum)
co-signatures for signing paths that need to outlive Ed25519.

## Measured

- 400 ms blocks, up to 5,000 transactions per block
- ~2,500 tx/s sustained ingestion through batched admission with parallel signature
  verification; 20,000–36,000 tx/s pure execution
- Rewards verified proportional to stake; unbonding released automatically at the
  release height with no claim transaction
