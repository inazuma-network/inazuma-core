# Inazuma Core — Test & Hardening Report

Status of every automated check that runs against this repository, what each one
proves, and what is still unproven. Regenerate with `cargo test`.

**Current result: 155 passed, 0 failed** (`cargo test`, release of this commit).

## 1. Where the tests live

| File | Kind | What it covers |
| --- | --- | --- |
| `src/*/tests` (inline `#[cfg(test)]`) | unit | Module-level invariants: signing bytes, SMT proofs, slashing math, websocket framing, rate limits |
| `src/battletest.rs` | adversarial | Attacks against a running node: equivocation, forged signatures, hostile WASM, fee manipulation |
| `src/fuzz.rs` | property | Randomised invariants: state-root immutability on failure, encoding injectivity, mempool ordering, replay determinism |
| `src/conformance.rs` | end-to-end | The 10-category pre-testnet checklist below, each test driving a real node from genesis |

`conformance.rs` builds a full node per test (genesis, bonded validator, sealed
blocks) rather than mocking, so a passing test means the assembled system
behaves, not just one function.

## 2. The ten categories

| § | Category | Representative checks |
| --- | --- | --- |
| 1 | Consensus | Parent-hash chaining, deterministic stake-weighted leader election, finality at >2/3 stake, reorg-depth ceiling, timestamp monotonicity and future-drift limit, block reward and supply inflation, halt/resume |
| 2 | Execution | Transfer debits/credits/nonce bump, insufficient balance, wrong chain ID, fee floor, bond/unbond/unjail state transitions, zero-amount and `u128::MAX` amounts |
| 3 | Networking | INSC1 handshake and magic, peer reputation and banning, global and per-IP connection caps, node-identity pinning and key-swap detection, frame size bounds |
| 4 | Mempool | Nonce ordering per sender, per-sender pending cap, global pool cap, fee-priority batch selection, eviction of the cheapest removable tail, EIP-1559 base-fee rise and decay to the floor |
| 5 | State & storage | SMT inclusion proof accept/reject, per-transaction and whole-block rollback, snapshot export/import roundtrip with root verification, startup state-root checkpoint |
| 6 | Contracts & tokens | WASM determinism, gas metering, stack-depth and memory-growth limits, host ABI, native token create/mint/transfer/burn and supply accounting |
| 7 | RPC | Every core read method answers, unknown methods error cleanly, `inaz_netInfo` self-redacts for anonymous callers, privileged methods refuse non-admin tiers, weighted rate limiting, websocket channel parse/reject |
| 8 | Load & stress | 500 transfers settle to exact balances, 200-block continuous run, many-account state-root stability |
| 9 | Security & fuzzing | Canonical-encoding injectivity, signature mutation resistance, delimiter injection, constant-time secret compare, hostile WASM containment, random-transaction fuzz never panics |
| 10 | Upgrades & forks | Height-gated activations (slashing, fee market, validator cap) replay pre-activation history unchanged; legacy v1 signatures still verify alongside canonical v2 |

## 3. Bugs this suite found and fixed

| ID | Severity | Finding | Fix |
| --- | --- | --- | --- |
| T-1 | High (remote DoS) | A transaction with `amount = u128::MAX` overflowed `amount + fee` while computing the required balance, panicking the node — one unsigned-cost transaction could crash every node that saw it | All balance-requirement and fee-collection arithmetic in `chain.rs` is saturating, so hostile amounts are rejected as unaffordable instead of aborting the process |
| T-2 | Medium (defence in depth) | The admin gate for `inaz_rpcLimits`, `inaz_halt`, `inaz_resume` and `inaz_prune` existed only in the HTTP handler; any other entry point reaching `dispatch_metered` bypassed it | The privileged-method check is enforced inside `dispatch_metered` as well, failing closed |
| T-3 | Low | Mempool nonce ordering could return a later nonce before an earlier one under a specific insert order (found by property test) | Ordering pass in `mempool.rs` now respects per-sender nonce sequence unconditionally |

Earlier hardening work (delimiter-free signed fields, canonical v2 encoding,
timestamp validation, journal-based atomicity, `inaz_netInfo` redaction, fork
credibility checks, max reorg depth) is described in
[spec.md](spec.md) and [SECURITY.md](../SECURITY.md).

## 4. Operational tests (run against the live devnet, not in CI)

| Test | Result |
| --- | --- |
| `kill -9` crash consistency | Recovers to last committed block; no torn state |
| Snapshot restore | Format-2 snapshot export from one node, import on another, state root matches |
| Node isolation and fork resolution | Isolated node re-syncs onto the credible chain after rejoining |
| Sustained soak | 72 h continuous load, 64 rotating wallets, transfers plus WASM deploys |
| Burst load | Peak 378.8 tx/s observed end-to-end, p95 latency tracked publicly on `/status` |
| Slashing in production | Downtime jailing and self-unjail observed on live validators |

## 5. What is still unproven

* **One implementation.** No independent client re-implements this spec, so a
  consensus bug here is a network-wide bug.
* **No external audit** and no funded bug bounty. Everything above is
  self-verified.
* **No machine-checked proof** of safety or liveness (no TLA+ model).
* **Sequential execution.** Throughput is bounded by design, not by hardware;
  parallel execution is unbuilt and untested.
* **Small validator set and low economic security.** Slashing only deters when
  the stake at risk exceeds the value of an attack.

These are the gaps that matter before mainnet — none of them are closed by
writing more tests.
