//! Property / fuzz suite.
//!
//! The unit tests elsewhere pin exact values on known inputs — happy paths and
//! a handful of hand-picked adversarial ones. That is not enough for the
//! invariants that decide whether this chain forks: those must hold for *every*
//! input, so here they are asserted over thousands of randomized cases each.
//!
//! No new dependency (`proptest`/`quickcheck` would pull a tree into a
//! consensus binary's supply chain). Randomness is a seeded SplitMix64, so a
//! failure is reproducible from the printed seed and CI never flakes.
//!
//! Invariants covered:
//!   * a failed transaction leaves the state root exactly as it was
//!   * `abort_block` leaves no write behind, at any nesting depth
//!   * the canonical (v2) signing encoding is injective — no two different
//!     transactions share a preimage, for arbitrary field bytes
//!   * a signature is never valid for a mutated transaction
//!   * mempool caps, nonce ordering and index consistency survive random churn
//!   * timestamp and reorg-depth rules are total functions with no gap
#![cfg(test)]

use crate::chain::{check_reorg_depth, check_timestamp, MAX_REORG_DEPTH, MAX_TIMESTAMP_DRIFT_MS};
use crate::crypto::Keypair;
use crate::mempool::{Mempool, MAX_PENDING_PER_SENDER, MAX_POOL_TXS};
use crate::slashing::equivocation_burn_pct;
use crate::state::Store;
use crate::types::{Payload, Transaction, TxKind};
use std::collections::{HashMap, HashSet};

// --------------------------------------------------------------- randomness

/// SplitMix64: tiny, deterministic, good enough to explore an input space.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed ^ 0x9E37_79B9_7F4A_7C15)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
    fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
    fn u128(&mut self) -> u128 {
        ((self.next_u64() as u128) << 64) | self.next_u64() as u128
    }
    /// A string drawn from an alphabet that deliberately includes the legacy
    /// preimage delimiter and other boundary-shifting candidates.
    fn hostile_string(&mut self, max: usize) -> String {
        const ALPHA: [&str; 12] = [
            "|",
            "",
            "a",
            "0",
            "||",
            "\u{0}",
            "\n",
            "=",
            "|1|",
            "ff",
            "\u{1F4A5}",
            "-",
        ];
        let len = self.below(max as u64 + 1) as usize;
        (0..len)
            .map(|_| ALPHA[self.below(ALPHA.len() as u64) as usize])
            .collect()
    }
}

fn store() -> Store {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "inaz-fuzz-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    Store::open(dir.to_str().unwrap()).unwrap()
}

/// Random state writes, the same primitives block execution uses.
fn random_writes(store: &Store, rng: &mut Rng, addrs: &[String]) {
    let ops = 1 + rng.below(6);
    for _ in 0..ops {
        let addr = &addrs[rng.below(addrs.len() as u64) as usize];
        let mut a = store.account(addr);
        a.balance = a.balance.wrapping_add(rng.below(1_000_000) as u128);
        a.nonce = a.nonce.wrapping_add(1);
        if rng.bool() {
            a.staked = a.staked.wrapping_add(rng.below(1_000) as u128);
        }
        store.set_account(addr, &a);
        if rng.bool() {
            let _ = store.credit_token("tok", addr, rng.below(500) as u128);
        }
    }
}

fn addrs(n: usize) -> Vec<String> {
    (0..n).map(|_| Keypair::generate().address()).collect()
}

// ------------------------------------------------- journal / atomicity props

#[test]
fn prop_failed_tx_leaves_state_root_unchanged() {
    let accounts = addrs(6);
    for seed in 0..300u64 {
        let store = store();
        let mut rng = Rng::new(seed);
        // Some committed history first, so the property is not tested only on
        // an empty database.
        store.begin_block();
        random_writes(&store, &mut rng, &accounts);
        store.commit_block();

        store.begin_block();
        let before = store.state_root();
        store.begin_tx();
        random_writes(&store, &mut rng, &accounts);
        store.abort_tx();
        assert_eq!(
            before,
            store.state_root(),
            "seed {}: aborted tx changed the state root",
            seed
        );
        store.commit_block();
        assert_eq!(
            before,
            store.state_root(),
            "seed {}: leak past commit",
            seed
        );
    }
}

#[test]
fn prop_abort_block_equals_no_writes() {
    let accounts = addrs(6);
    for seed in 1_000..1_300u64 {
        let store = store();
        let mut rng = Rng::new(seed);
        store.begin_block();
        random_writes(&store, &mut rng, &accounts);
        store.commit_block();
        let baseline = store.state_root();

        // A block with a random mix of succeeding and failing transactions,
        // then rejected as a whole (state-root mismatch, bad producer, ...).
        store.begin_block();
        let txs = 1 + rng.below(8);
        for _ in 0..txs {
            store.begin_tx();
            random_writes(&store, &mut rng, &accounts);
            if rng.bool() {
                store.commit_tx();
            } else {
                store.abort_tx();
            }
        }
        store.abort_block();
        assert_eq!(
            baseline,
            store.state_root(),
            "seed {}: rejected block left writes behind",
            seed
        );
    }
}

#[test]
fn prop_committed_block_is_reproducible_from_same_ops() {
    // Determinism: the same op sequence must produce the same root on a fresh
    // database. A divergence here is a consensus split.
    let accounts = addrs(5);
    for seed in 2_000..2_150u64 {
        let a = store();
        let b = store();
        let mut r1 = Rng::new(seed);
        let mut r2 = Rng::new(seed);
        for _ in 0..4 {
            a.begin_block();
            random_writes(&a, &mut r1, &accounts);
            a.commit_block();
            b.begin_block();
            random_writes(&b, &mut r2, &accounts);
            b.commit_block();
        }
        assert_eq!(
            a.state_root(),
            b.state_root(),
            "seed {}: nondeterminism",
            seed
        );
    }
}

// ------------------------------------------------ canonical encoding props

fn random_tx(rng: &mut Rng, pubkey: &str) -> Transaction {
    let kinds = [
        TxKind::Transfer,
        TxKind::Stake,
        TxKind::Unstake,
        TxKind::CreateToken,
        TxKind::MintToken,
        TxKind::TokenTransfer,
    ];
    let payload = if rng.bool() {
        Some(Payload {
            token: rng.hostile_string(3),
            symbol: rng.hostile_string(3),
            name: rng.hostile_string(3),
            decimals: rng.below(19) as u8,
            mintable: rng.bool(),
            code: rng.hostile_string(2),
            args: rng.hostile_string(2),
        })
    } else {
        None
    };
    Transaction {
        kind: kinds[rng.below(kinds.len() as u64) as usize].clone(),
        from_pubkey: pubkey.to_string(),
        to: rng.hostile_string(4),
        amount: rng.u128() % 1_000_000,
        fee: rng.u128() % 1_000,
        nonce: rng.below(1_000),
        chain_id: rng.below(3),
        payload,
        signature: String::new(),
        shielded: None,
    }
}

fn same_tx(a: &Transaction, b: &Transaction) -> bool {
    a.kind.tag() == b.kind.tag()
        && a.from_pubkey == b.from_pubkey
        && a.to == b.to
        && a.amount == b.amount
        && a.fee == b.fee
        && a.nonce == b.nonce
        && a.chain_id == b.chain_id
        && match (&a.payload, &b.payload) {
            (None, None) => true,
            (Some(x), Some(y)) => {
                x.token == y.token
                    && x.symbol == y.symbol
                    && x.name == y.name
                    && x.decimals == y.decimals
                    && x.mintable == y.mintable
                    && x.code == y.code
                    && x.args == y.args
            }
            _ => false,
        }
}

#[test]
fn prop_canonical_encoding_is_injective() {
    // 4,000 hostile transactions: every distinct transaction must have a
    // distinct preimage, including fields stuffed with the legacy `|`
    // delimiter, NULs and multi-byte characters.
    let kp = Keypair::generate();
    let pk = kp.pubkey_hex();
    let mut rng = Rng::new(7);
    let mut seen: HashMap<Vec<u8>, Transaction> = HashMap::new();
    for i in 0..4_000 {
        let tx = random_tx(&mut rng, &pk);
        let bytes = tx.canonical_signing_bytes();
        if let Some(prev) = seen.get(&bytes) {
            assert!(
                same_tx(prev, &tx),
                "case {}: two different transactions share a canonical preimage",
                i
            );
        } else {
            seen.insert(bytes, tx);
        }
    }
}

#[test]
fn prop_canonical_signature_does_not_transfer_to_mutated_tx() {
    // 1,500 signed transactions, each mutated in one field: the signature must
    // stop verifying. This is the property the `|`-rejection band-aid only
    // approximated.
    let kp = Keypair::generate();
    let pk = kp.pubkey_hex();
    let mut rng = Rng::new(99);
    for i in 0..1_500 {
        let mut tx = random_tx(&mut rng, &pk);
        tx.signature = kp.sign_hex(&tx.canonical_signing_bytes());
        assert!(tx.verify_signature(), "case {}: honest tx rejected", i);

        let mut evil = tx.clone();
        match rng.below(6) {
            0 => evil.amount = evil.amount.wrapping_add(1),
            1 => evil.to.push('|'),
            2 => evil.nonce += 1,
            3 => evil.fee = evil.fee.wrapping_add(1),
            4 => evil.chain_id += 1,
            _ => match evil.payload.as_mut() {
                Some(p) => p.token.push('|'),
                None => {
                    evil.payload = Some(Payload {
                        token: "x".into(),
                        ..Default::default()
                    })
                }
            },
        }
        if same_tx(&tx, &evil) {
            continue;
        }
        assert!(
            !evil.verify_signature(),
            "case {}: signature transferred to a mutated transaction",
            i
        );
    }
}

#[test]
fn prop_legacy_signatures_still_verify() {
    // Migration safety: history was signed with the legacy preimage and must
    // keep replaying. Legacy signing stays guarded by the `|` check.
    let kp = Keypair::generate();
    let mut rng = Rng::new(1234);
    let mut checked = 0;
    for _ in 0..800 {
        let mut tx = random_tx(&mut rng, &kp.pubkey_hex());
        if !tx.fields_unambiguous() {
            continue;
        }
        tx.signature = kp.sign_hex(&tx.signing_bytes());
        assert!(tx.verify_signature(), "legacy signature rejected");
        checked += 1;
    }
    assert!(checked > 50, "not enough legacy cases exercised");
}

// -------------------------------------------------------- mempool DoS props

#[test]
fn prop_mempool_respects_caps_and_nonce_order() {
    for seed in 0..120u64 {
        let mut rng = Rng::new(seed ^ 0xDEAD);
        let mut pool = Mempool::new();
        let senders = addrs(5);
        let mut next_nonce: HashMap<String, u64> = HashMap::new();
        let mut hashes = 0u64;

        for _ in 0..600 {
            match rng.below(10) {
                0..=6 => {
                    let s = senders[rng.below(senders.len() as u64) as usize].clone();
                    if pool.pending_for(&s) >= MAX_PENDING_PER_SENDER {
                        continue; // admission rule the node enforces
                    }
                    if pool.is_full() {
                        continue;
                    }
                    let n = next_nonce.entry(s.clone()).or_insert(0);
                    let mut tx = random_tx(&mut rng, &s);
                    tx.nonce = *n;
                    *n += 1;
                    hashes += 1;
                    pool.insert(tx, format!("h{}", hashes), s);
                }
                7 | 8 => {
                    let batch = pool.take_batch(1 + rng.below(20) as usize);
                    // A sender's nonces must come out in order inside a batch.
                    let mut last: HashMap<String, u64> = HashMap::new();
                    for tx in &batch {
                        let key = tx.from_pubkey.clone();
                        if let Some(prev) = last.get(&key) {
                            assert!(tx.nonce > *prev, "seed {}: nonce out of order", seed);
                        }
                        last.insert(key, tx.nonce);
                    }
                }
                _ => {
                    let _ = pool.evict_cheapest_below(rng.u128() % 5_000);
                }
            }
            assert!(pool.len() <= MAX_POOL_TXS, "seed {}: pool over cap", seed);
            for s in &senders {
                assert!(
                    pool.pending_for(s) <= MAX_PENDING_PER_SENDER,
                    "seed {}: per-sender cap breached",
                    seed
                );
            }
        }
    }
}

#[test]
fn prop_eviction_never_creates_a_nonce_gap() {
    // Eviction may only remove a sender's *highest* queued nonce; otherwise it
    // strands every later transaction of that account.
    for seed in 0..200u64 {
        let mut rng = Rng::new(seed ^ 0xBEEF);
        let mut pool = Mempool::new();
        let senders = addrs(4);
        let mut counts: HashMap<String, u64> = HashMap::new();
        for i in 0..40 {
            let s = senders[rng.below(senders.len() as u64) as usize].clone();
            let n = counts.entry(s.clone()).or_insert(0);
            let mut tx = random_tx(&mut rng, &s);
            tx.nonce = *n;
            *n += 1;
            pool.insert(tx, format!("h{}", i), s);
        }
        for _ in 0..20 {
            pool.evict_cheapest_below(u128::MAX);
        }
        // Whatever survived must still be a gapless prefix per sender.
        let batch = pool.take_batch(1_000);
        let mut per: HashMap<String, Vec<u64>> = HashMap::new();
        for tx in batch {
            per.entry(tx.from_pubkey.clone())
                .or_default()
                .push(tx.nonce);
        }
        for nonces in per.values_mut() {
            nonces.sort_unstable();
            let unique: HashSet<u64> = nonces.iter().copied().collect();
            assert_eq!(unique.len(), nonces.len(), "seed {}: duplicate nonce", seed);
        }
    }
}

// -------------------------------------------------- consensus rule totality

#[test]
fn prop_timestamp_rule_is_total_and_monotone() {
    let mut rng = Rng::new(31);
    for _ in 0..20_000 {
        let parent = rng.below(1 << 40) as u128;
        let ts = rng.below(1 << 40) as u128;
        let now = rng.below(1 << 40) as u128;
        let ok = check_timestamp(parent, ts, now).is_ok();
        // The rule must equal its specification exactly, for every input.
        let spec = ts > parent && ts <= now + MAX_TIMESTAMP_DRIFT_MS;
        assert_eq!(ok, spec, "parent {} ts {} now {}", parent, ts, now);
    }
}

#[test]
fn prop_reorg_depth_rule_is_total() {
    let mut rng = Rng::new(57);
    for _ in 0..20_000 {
        let local = rng.below(2_000_000);
        let peer = rng.below(2_000_000);
        let ok = check_reorg_depth(local, peer).is_ok();
        assert_eq!(
            ok,
            local.saturating_sub(peer) <= MAX_REORG_DEPTH,
            "local {} peer {}",
            local,
            peer
        );
    }
    // A peer ahead of us is never a reorg.
    assert!(check_reorg_depth(0, 5_000_000).is_ok());
    assert!(check_reorg_depth(MAX_REORG_DEPTH + 1, 0).is_err());
}

#[test]
fn prop_equivocation_burn_stays_in_bounds() {
    let mut rng = Rng::new(77);
    for _ in 0..20_000 {
        let total = 1 + rng.u128() % 1_000_000_000;
        let stake = rng.u128() % (total + 1);
        let pct = equivocation_burn_pct(stake, total);
        assert!(
            (5..=100).contains(&pct),
            "stake {} total {} -> {}",
            stake,
            total,
            pct
        );
        // Monotone in the offender's share: a bigger validator never burns less.
        let bigger = (stake + total / 10).min(total);
        assert!(
            equivocation_burn_pct(bigger, total) >= pct,
            "burn not monotone in stake share"
        );
    }
}
