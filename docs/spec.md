# Inazuma Core — Consensus Specification (v0.2)

Normative reference for the state transition and consensus rules. Any second
client implementation must match this byte-for-byte; where this document and the
code disagree, the code is the current chain and this document is the bug.

## 1. Constants

| Name | Value | Where |
| --- | --- | --- |
| `CHAIN_ID` | 7777 | `types.rs` |
| Block time | 400 ms | genesis `block_time_ms` |
| `MIN_STAKE` | 1,000 INAZ | `types.rs` |
| `MIN_FEE` | 1 rai | `types.rs` |
| `MAX_TXS_PER_BLOCK` | 5,000 | `chain.rs` |
| `MAX_TIMESTAMP_DRIFT_MS` | 12,000 | `chain.rs` |
| `MIN_TIMESTAMP_SPACING_MS` | 1 | `chain.rs` |
| `MAX_LEADER_ATTEMPTS` | 4,096 (+2 slack on import) | `chain.rs` |
| `MAX_REORG_DEPTH` | 5,000 | `chain.rs` |
| `MAX_VALIDATORS` | 100 (activation height gated) | `staking.rs` |
| `MAX_POOL_TXS` | 20,000 | `mempool.rs` |
| `MAX_PENDING_PER_SENDER` | 64 | `mempool.rs` |
| Finality threshold | > 2/3 of active stake | `consensus.rs` |
| Equivocation burn | 5% floor, 100% cap, correlation term | `slashing.rs` |
| Downtime jail | 50 consecutive missed slots | `types.rs` |

## 2. Accounts and state

State is the set of accounts, tokens, token balances, contracts and contract
storage. `state_root` is SHA-256 over every table serialized in key order
(`state.rs::state_root`). A Sparse Merkle Tree (`smt.rs`, depth 256) provides
inclusion proofs over the same data.

Determinism rules: no wall-clock reads, no floats, no map iteration order in
anything reachable from `state_root`.

## 3. Transaction encoding and signatures

Two accepted preimages:

1. **Legacy (v1)** — ASCII fields joined with `|`, prefix `inazuma-tx`. Only
   valid when every signed string field is free of `|` (`fields_unambiguous`).
   Retained so existing history replays byte-identically.
2. **Canonical (v2)** — domain tag `inazuma-tx-v2`, then every field
   length-prefixed: strings as `u32` big-endian length + bytes, integers as
   fixed-width big-endian, payload presence as a `0`/`1` byte
   (`types.rs::canonical_signing_bytes`). Structurally unambiguous; no field
   content can shift another field's boundary.

`verify_signature` tries v2 first, then v1. New signers MUST use v2. Signatures
are ed25519; the sender address is base58 of a domain-separated hash of the
public key.

## 4. Block validity

A block at height `h` with parent `p` is valid iff:

1. `parent_hash == hash(p)` and `height == p.height + 1`.
2. `check_timestamp(p.timestamp, ts, now)`: `ts > p.timestamp` and
   `ts <= now + MAX_TIMESTAMP_DRIFT_MS`.
3. `producer` derives from `producer_pubkey`, and the header signature verifies
   over `header_bytes` (domain `inazuma-block`, includes `CHAIN_ID`).
4. `producer` is the elected leader for `h` at some attempt
   `a <= leader_attempt_window(p.timestamp, ts, now, slot_ms)`. Leader election
   is deterministic and stake-weighted over the validator set at `h`.
5. `producer` is neither jailed nor tombstoned.
6. `txs_root` equals the binary Merkle root over transaction hashes.
7. Every transaction signature verifies (§3) and `tx.chain_id == CHAIN_ID`.
8. Executing the transactions in order yields exactly `state_root`.

## 5. Execution atomicity

Execution is journalled (`journal.rs`), not overlay-based. The importer opens a
block frame and a per-transaction frame. A failed transaction is rolled back to
its own savepoint and dropped from the block; a block that fails any check —
including the `state_root` comparison in step 8 — is rolled back entirely, so a
rejecting node's state is bit-identical to its pre-block state.

Invariants asserted by property tests (`fuzz.rs`): *any* failed transaction
leaves `state_root` unchanged; `abort_block` is indistinguishable from having
performed no writes; the same operation sequence yields the same root on a
fresh database.

## 6. Finality

Validators broadcast domain-separated precommit votes over `(height, hash)`.
A height is final once votes representing more than 2/3 of active stake are
collected for one hash. Finalized history is never reorged: an unwind below the
finalized height is refused, and an unwind deeper than `MAX_REORG_DEPTH` blocks
is refused even when nothing is finalized (long-range attack bound) and requires
operator action.

On startup a node recomputes `state_root` and compares it to the root its own
tip block committed to. A mismatch halts the node instead of letting it produce
or vote on divergent state.

## 7. Slashing

* **Equivocation** — two conflicting signed blocks or votes at one height.
  Anyone may submit the evidence as a `ReportEquivocation` transaction. Burn is
  `equivocation_burn_pct(offender_stake, total_stake)`: 5% floor, plus a
  correlation term rising with the offender's stake share, capped at 100%. The
  offender is tombstoned permanently.
* **Downtime** — 50 consecutive missed slots jails the validator; repeat offences
  burn `DOWNTIME_REPEAT_BURN_BPS`. Release requires an `Unjail` transaction after
  the jail period.
* Rules activate at `SLASHING_ACTIVATION_HEIGHT` so pre-activation history
  replays unchanged.

## 8. Fees

EIP-1559-style base fee, ±12% per block toward a target occupancy, active from
`FEE_MARKET_ACTIVATION_HEIGHT`, clamped at `MAX_BASE_FEE`. Fees currently go to
the block producer; burning is a future, height-gated change.

## 9. Networking

Custom TCP gossip. Sessions are INSC1: X25519 ECDH, HKDF-SHA256, ChaCha20-Poly1305,
with the node's ed25519 key authenticating the handshake. Nodes may require
encryption and pin an allowlist of node keys. Per-IP token-bucket rate limits,
global and per-IP connection caps, bounded frame sizes, and peer reputation
scoring with temporary bans are enforced on every inbound connection.

## 10. Known gaps (not yet specified or built)

* One client implementation; no independent re-implementation of this spec.
* No external audit, no funded bug bounty.
* No TLA+ or machine-checked safety/liveness proof.
* Governance is operator-driven; no timelock.