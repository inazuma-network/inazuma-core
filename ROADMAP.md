# Roadmap

Honest status, not marketing. Anything not listed as done is not done.

## Shipped

| Area | State |
| --- | --- |
| Consensus | Stake-weighted proposer, 400 ms target block time |
| Accounts | Ed25519, base58 addresses, `inazkey1` export format |
| Post-quantum | Optional ML-DSA-65 co-signature path |
| Staking | Bond, unbond, active-set selection |
| Slashing | Equivocation burn + tombstone, downtime jailing (active from block 130,000) |
| Fees | Dynamic base fee with priority tips |
| Mempool | Indexed, O(1) admission, per-account caps, fee-based eviction |
| P2P | Encrypted transport (X25519 + ChaCha20-Poly1305), peer pinning, inbound caps |
| RPC | JSON-RPC, tiers with weighted rate limits, account throttling |
| WebSocket | Subscriptions for heads, finality, mempool, logs |
| State proofs | Sparse Merkle tree, `inaz_getProof` (active from block 200,000) |
| Contracts | WASM execution with a documented host ABI |
| Replicas | `--replica` read-only nodes for horizontal RPC scale |

## Next

| Item | Why it matters | Status |
| --- | --- | --- |
| Historical indexer | Explorers and wallets need transaction history without scanning every block | Design |
| Larger validator set | More independent operators, less trust in the founding nodes | Ongoing, operator by operator |
| Light client library | Verify state from a phone or browser without a trusted RPC | Design, built on state proofs |
| Deterministic gas metering audit | Guarantee identical contract cost on every node | Planned |
| Fuzzing in CI | Catch consensus divergence before release, not after | Planned |

## Later

| Item | Notes |
| --- | --- |
| Blob-style expiring data | Cheap data availability so rollups do not bloat state forever |
| Proof verifier precompile | Required before any real ZK rollup can settle here |
| Canonical bridge contract | Proof-gated deposits and withdrawals |
| Multiple node implementations | A second independent client is what makes a network hard to kill |

## Explicitly not planned

- Changing the total supply or minting outside the documented reward schedule.
- Admin keys able to freeze accounts or reverse transactions.
- Any upgrade path that skips an activation height.
