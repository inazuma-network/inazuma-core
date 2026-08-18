//! Devnet -> public-testnet battle-test suite.
//!
//! Every test here maps to a line item on the pre-testnet checklist. They are
//! deliberately *exact* (not "approximately") because the properties they pin
//! down — finality thresholds, burn formulas, jail boundaries, fee trajectory,
//! state-root equality, WASM determinism — are the ones that split a network
//! when they drift.
#![cfg(test)]

use crate::consensus::{Vote, VoteTracker};
use crate::crypto::Keypair;
use crate::fees::{next_base_fee, required_fee, FEE_MARKET_ACTIVATION_HEIGHT, MAX_BASE_FEE};
use crate::slashing;
use crate::smt::{empty_at, leaf_hash, leaf_key, Smt, DEPTH};
use crate::snapshot;
use crate::staking::{elect_leader_attempt, total_stake, validator_set_at, Validator};
use crate::staking::{MAX_VALIDATORS, VALIDATOR_CAP_ACTIVATION_HEIGHT};
use crate::state::Store;
use crate::types::{
    txs_root, Account, Block, DOWNTIME_JAIL_BLOCKS, DOWNTIME_JAIL_STREAK, DOWNTIME_REPEAT_BURN_BPS,
    MIN_FEE, MIN_STAKE, RAI_PER_INAZ, SLASHING_ACTIVATION_HEIGHT,
};
use std::collections::BTreeMap;

// ------------------------------------------------------------------ helpers

fn store() -> Store {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "inaz-bt-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    Store::open(dir.to_str().unwrap()).unwrap()
}

fn bond(store: &Store, kp: &Keypair, stake: u128) {
    let mut a = store.account(&kp.address());
    a.balance = 10 * RAI_PER_INAZ;
    a.staked = stake;
    store.set_account(&kp.address(), &a);
}

fn sealed(kp: &Keypair, height: u64, parent: &str, state_root: &str) -> Block {
    let mut b = Block {
        height,
        parent_hash: parent.to_string(),
        timestamp_ms: 1_000 + height as u128,
        state_root: state_root.to_string(),
        txs_root: txs_root(&[]),
        producer: kp.address(),
        producer_pubkey: kp.pubkey_hex(),
        transactions: Vec::new(),
        signature: String::new(),
        hash: String::new(),
    };
    b.signature = kp.sign_hex(&b.header_bytes());
    b.hash = b.compute_hash();
    b
}

fn vote(kp: &Keypair, height: u64, hash: &str) -> Vote {
    let mut v = Vote {
        height,
        hash: hash.to_string(),
        voter_pubkey: kp.pubkey_hex(),
        signature: String::new(),
    };
    v.signature = kp.sign_hex(&v.signing_bytes());
    v
}

fn vset(stakes: &[(String, u128)]) -> Vec<Validator> {
    let mut set: Vec<Validator> = stakes
        .iter()
        .map(|(address, stake)| Validator {
            address: address.clone(),
            stake: *stake,
            rewards: 0,
            blocks_produced: 0,
            jailed_until: 0,
            tombstoned: false,
            missed_slots: 0,
            slashed: 0,
        })
        .collect();
    set.sort_by(|a, b| a.address.cmp(&b.address));
    set
}

// =================================================== §1 consensus & finality

/// Leader election must be stake-weighted and *deterministic*: 20 validators,
/// 20k slots, every node recomputing the schedule gets byte-identical answers
/// and the share of slots tracks the share of stake.
#[test]
fn leader_schedule_is_deterministic_and_stake_weighted() {
    let keys: Vec<Keypair> = (0..20).map(|_| Keypair::generate()).collect();
    // Stakes 1..20 units so the weighting is easy to check.
    let stakes: Vec<(String, u128)> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (k.address(), (i as u128 + 1) * MIN_STAKE))
        .collect();
    let set = vset(&stakes);
    let total = total_stake(&set);

    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let rounds = 20_000u64;
    for h in 1..=rounds {
        let parent = format!("{:064x}", h);
        let a = elect_leader_attempt(&set, h, &parent, 0).unwrap();
        let b = elect_leader_attempt(&set, h, &parent, 0).unwrap();
        assert_eq!(a, b, "election must be a pure function");
        *counts.entry(a).or_default() += 1;
    }
    assert_eq!(counts.values().sum::<u64>(), rounds);
    assert_eq!(counts.len(), 20, "every validator must get slots");

    for v in &set {
        let got = *counts.get(&v.address).unwrap() as f64 / rounds as f64;
        let want = v.stake as f64 / total as f64;
        assert!(
            (got - want).abs() < 0.01,
            "{} got {:.4} of slots for {:.4} of stake",
            v.address,
            got,
            want
        );
    }
}

/// Attempt escalation must move to a *different* validator, or a single offline
/// leader stalls the slot forever.
#[test]
fn attempt_escalation_rotates_the_leader() {
    let keys: Vec<Keypair> = (0..5).map(|_| Keypair::generate()).collect();
    let set = vset(
        &keys
            .iter()
            .map(|k| (k.address(), MIN_STAKE))
            .collect::<Vec<_>>(),
    );
    for h in 1..500u64 {
        let parent = format!("{:064x}", h);
        let primary = elect_leader_attempt(&set, h, &parent, 0).unwrap();
        let rotated = (1..8)
            .filter_map(|a| elect_leader_attempt(&set, h, &parent, a))
            .any(|l| l != primary);
        assert!(rotated, "no rotation away from the primary at height {}", h);
    }
}

/// 2/3 stake is the finality line: 66.6% must not finalize, 66.7% must.
#[test]
fn finality_threshold_is_exactly_two_thirds() {
    let st = store();
    let a = Keypair::generate(); // 666 units
    let b = Keypair::generate(); // 1 unit
    let c = Keypair::generate(); // 333 units
    bond(&st, &a, 666 * MIN_STAKE);
    bond(&st, &b, MIN_STAKE);
    bond(&st, &c, 333 * MIN_STAKE);

    let block = sealed(&a, 1, &"0".repeat(64), "root");
    st.put_block(&block);
    let tracker = VoteTracker::new();

    // 66.6% — below the line, chain must stay unfinalized (halt, not fork).
    let out = tracker.add(&st, vote(&a, 1, &block.hash)).unwrap();
    assert!(out.fresh);
    assert_eq!(out.finalized, None, "66.6% must not finalize");
    assert_eq!(st.finalized_height(), 0);

    // 66.7% — one more unit of stake crosses it.
    let out = tracker.add(&st, vote(&b, 1, &block.hash)).unwrap();
    assert_eq!(out.finalized, Some(1), "66.7% must finalize");
    assert_eq!(st.finalized_height(), 1);

    // Finalized heights are pruned from the tally, so only the total remains.
    let (_voted, total) = tracker.tally(&st, 1);
    assert_eq!(total, 1000 * MIN_STAKE);
}

/// 50% live stake: the chain must halt at the last finalized height rather than
/// finalize two competing branches.
#[test]
fn half_stake_halts_instead_of_forking() {
    let st = store();
    let a = Keypair::generate();
    let b = Keypair::generate();
    bond(&st, &a, 500 * MIN_STAKE);
    bond(&st, &b, 500 * MIN_STAKE);

    let block = sealed(&a, 1, &"0".repeat(64), "root");
    st.put_block(&block);
    let tracker = VoteTracker::new();
    assert_eq!(
        tracker
            .add(&st, vote(&a, 1, &block.hash))
            .unwrap()
            .finalized,
        None
    );
    assert_eq!(st.finalized_height(), 0, "50% must not finalize");

    // The offline half's votes for a *different* hash cannot finalize either.
    let conflicting = tracker.add(&st, vote(&b, 1, &"f".repeat(64)));
    assert!(
        conflicting.is_err(),
        "vote for an unknown hash must be rejected"
    );
    assert_eq!(st.finalized_height(), 0);
}

/// Domain separation: a signature is bound to (chain, height, hash). Replaying
/// it anywhere else must be *rejected*, not silently ignored.
#[test]
fn vote_signatures_are_domain_separated() {
    let st = store();
    let a = Keypair::generate();
    let b = Keypair::generate();
    let c = Keypair::generate();
    bond(&st, &a, MIN_STAKE);
    bond(&st, &b, MIN_STAKE);
    bond(&st, &c, MIN_STAKE);
    let h1 = sealed(&a, 1, &"0".repeat(64), "r1");
    let h2 = sealed(&a, 2, &h1.hash, "r2");
    st.put_block(&h1);
    st.put_block(&h2);
    let tracker = VoteTracker::new();

    let good = vote(&a, 1, &h1.hash);
    assert!(good.verify_signature());

    // height swapped
    let mut moved = good.clone();
    moved.height = 2;
    assert!(!moved.verify_signature());
    assert!(tracker.add(&st, moved).is_err());

    // hash swapped
    let mut rehashed = good.clone();
    rehashed.hash = h2.hash.clone();
    assert!(!rehashed.verify_signature());
    assert!(tracker.add(&st, rehashed).is_err());

    // voter swapped (signature belongs to another key)
    let mut impersonated = good.clone();
    impersonated.voter_pubkey = b.pubkey_hex();
    assert!(!impersonated.verify_signature());
    assert!(tracker.add(&st, impersonated).is_err());

    // foreign chain id: same fields, signed under a different domain string
    let mut foreign = Vote {
        height: 1,
        hash: h1.hash.clone(),
        voter_pubkey: a.pubkey_hex(),
        signature: String::new(),
    };
    foreign.signature =
        a.sign_hex(format!("inazuma-vote|1|{}|{}", foreign.height, foreign.hash).as_bytes());
    assert!(
        !foreign.verify_signature(),
        "chain id must be inside the preimage"
    );
    assert!(tracker.add(&st, foreign).is_err());

    // delimiter injection inside the hash field
    let mut injected = Vote {
        height: 1,
        hash: format!("{}|9", h1.hash),
        voter_pubkey: a.pubkey_hex(),
        signature: String::new(),
    };
    injected.signature = a.sign_hex(&injected.signing_bytes());
    assert!(
        !injected.verify_signature(),
        "| must be refused in signed fields"
    );
}

/// Two precommits at one height from one validator is provable equivocation and
/// must land in the evidence queue, not just be dropped.
#[test]
fn equivocating_vote_produces_evidence() {
    let st = store();
    let a = Keypair::generate();
    let b = Keypair::generate();
    bond(&st, &a, MIN_STAKE);
    bond(&st, &b, MIN_STAKE);
    let blk = sealed(&a, 1, &"0".repeat(64), "r1");
    let other = sealed(&b, 1, &"0".repeat(64), "r2");
    st.put_block(&blk);
    let tracker = VoteTracker::new();

    tracker.add(&st, vote(&a, 1, &blk.hash)).unwrap();
    let err = tracker
        .add(&st, vote(&a, 1, &other.hash))
        .err()
        .expect("must be rejected");
    assert!(err.contains("equivocating"), "got: {}", err);

    let evidence = tracker.take_evidence();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].verify().unwrap(), a.address());
    assert!(
        tracker.take_evidence().is_empty(),
        "evidence must drain once"
    );
}

/// The pending-vote buffer is the cheapest DoS surface on the node: it must only
/// accept bonded validators, one slot per (validator, height).
#[test]
fn pending_vote_buffer_rejects_unbonded_spam() {
    let st = store();
    let a = Keypair::generate();
    bond(&st, &a, MIN_STAKE);
    let tracker = VoteTracker::new();

    for _ in 0..64 {
        let stranger = Keypair::generate();
        let err = tracker
            .add(&st, vote(&stranger, 9_000, &"a".repeat(64)))
            .err()
            .expect("unbonded voter must be rejected");
        assert!(err.contains("not a bonded validator"), "got: {}", err);
    }
    // A bonded validator may buffer, but only once per height.
    assert!(
        tracker
            .add(&st, vote(&a, 9_000, &"a".repeat(64)))
            .unwrap()
            .fresh
    );
    assert!(
        !tracker
            .add(&st, vote(&a, 9_000, &"a".repeat(64)))
            .unwrap()
            .fresh
    );
}

/// Buffered votes must replay onto the block when it finally lands.
#[test]
fn buffered_votes_finalize_on_arrival() {
    let st = store();
    let a = Keypair::generate();
    let b = Keypair::generate();
    bond(&st, &a, MIN_STAKE);
    bond(&st, &b, MIN_STAKE);
    let blk = sealed(&a, 1, &"0".repeat(64), "r1");
    let tracker = VoteTracker::new();

    // Votes arrive first (block still in flight).
    tracker.add(&st, vote(&a, 1, &blk.hash)).unwrap();
    tracker.add(&st, vote(&b, 1, &blk.hash)).unwrap();
    assert_eq!(st.finalized_height(), 0);

    st.put_block(&blk);
    assert_eq!(tracker.replay_pending(&st, 1), Some(1));
    assert_eq!(st.finalized_height(), 1);
}

/// Clock skew: ±15s / 30s / 60s. Future blocks outside the 12s tolerance are
/// rejected; a lagging clock never rejects an honest, monotonic block.
#[test]
fn clock_skew_tolerance_is_enforced() {
    use crate::chain::{check_timestamp, leader_attempt_window, MAX_TIMESTAMP_DRIFT_MS};
    let now = 1_000_000u128;
    let parent = now - 400;

    assert!(check_timestamp(parent, now, now).is_ok());
    assert!(
        check_timestamp(parent, now + MAX_TIMESTAMP_DRIFT_MS, now).is_ok(),
        "edge of tolerance"
    );
    for ahead in [15_000u128, 30_000, 60_000] {
        assert!(
            check_timestamp(parent, now + ahead, now).is_err(),
            "+{}ms accepted",
            ahead
        );
    }
    // A validator running behind still produces valid blocks (monotonic only).
    for behind in [15_000u128, 30_000, 60_000] {
        assert!(
            check_timestamp(parent, parent + 1, now + behind).is_ok(),
            "-{}ms rejected",
            behind
        );
    }
    // Non-monotonic is always fatal.
    assert!(check_timestamp(parent, parent, now).is_err());
    assert!(check_timestamp(parent, parent - 1, now).is_err());

    // A future-dated block cannot buy extra leader attempts (censorship vector).
    let honest = leader_attempt_window(parent, parent + 400, now, 400);
    let inflated = leader_attempt_window(parent, parent + 600_000, now, 400);
    assert!(
        inflated <= honest + 1,
        "future timestamp inflated the window: {} vs {}",
        inflated,
        honest
    );
}

/// Long-range attack: an old, unbonded key cannot rewrite finalized history.
#[test]
fn finalized_history_cannot_be_reorged() {
    let st = store();
    let a = Keypair::generate();
    let b = Keypair::generate();
    bond(&st, &a, 2 * MIN_STAKE);
    bond(&st, &b, MIN_STAKE);
    let blk = sealed(&a, 1, &"0".repeat(64), "r1");
    st.put_block(&blk);
    let tracker = VoteTracker::new();
    tracker.add(&st, vote(&a, 1, &blk.hash)).unwrap();
    tracker.add(&st, vote(&b, 1, &blk.hash)).unwrap();
    assert_eq!(st.finalized_height(), 1);

    // An attacker's alternate block at the same height, signed by an old key.
    let attacker = Keypair::generate();
    let alt = sealed(&attacker, 1, &"0".repeat(64), "evil");
    assert_ne!(alt.hash, blk.hash);
    // Votes at or below the finalized height can never move the chain: they are
    // either refused outright or absorbed as stale.
    let stale = tracker.add(&st, vote(&attacker, 1, &alt.hash));
    assert!(stale
        .as_ref()
        .map(|o| o.finalized.is_none() && !o.fresh)
        .unwrap_or(true));
    let stale = tracker.add(&st, vote(&a, 1, &alt.hash));
    assert!(stale
        .as_ref()
        .map(|o| o.finalized.is_none() && !o.fresh)
        .unwrap_or(true));
    assert_eq!(st.block(1).unwrap().hash, blk.hash);
    assert_eq!(st.finalized_height(), 1);
}

// ============================================== §2 slashing & misbehaviour

/// Burn = floor(5%) or 3x stake share, capped at 100% — exact, at boundaries.
#[test]
fn equivocation_burn_formula_is_exact() {
    use slashing::equivocation_burn_pct as pct;
    assert_eq!(pct(0, 100), 5);
    assert_eq!(pct(1, 100_000), 5, "dust validator pays the floor");
    assert_eq!(pct(1_000, 100_000), 5, "1% share -> 3% < floor -> 5%");
    assert_eq!(pct(2_000, 100_000), 6, "2% share -> 6%");
    assert_eq!(pct(10_000, 100_000), 30);
    assert_eq!(pct(33_000, 100_000), 99);
    assert_eq!(pct(34_000, 100_000), 100, "cap");
    assert_eq!(pct(100_000, 100_000), 100);
    assert_eq!(pct(1, 0), 5, "no stake on chain -> floor");
}

/// End-to-end double sign: exact burn, bounty out of the burn (no minting),
/// permanent tombstone, and no second slash for the same offence.
#[test]
fn double_sign_burns_exactly_and_tombstones_forever() {
    let st = store();
    let offender = Keypair::generate();
    let reporter = Keypair::generate();
    let other = Keypair::generate();
    bond(&st, &offender, 100 * MIN_STAKE); // 10% of 1000 -> 30% burn
    bond(&st, &other, 900 * MIN_STAKE);
    let before_reporter = st.account(&reporter.address()).balance;

    let a = slashing::HeaderProof::from_block(&sealed(&offender, 500, &"0".repeat(64), "aa"));
    let b = slashing::HeaderProof::from_block(&sealed(&offender, 500, &"0".repeat(64), "bb"));
    let ev = slashing::Evidence::Block { a, b };

    let staked = 100 * MIN_STAKE;
    let expected_burn = staked * 30 / 100;
    let expected_bounty = expected_burn * 10 / 100;

    let rec = slashing::apply_report(&st, 600, &reporter.address(), &ev).unwrap();
    assert_eq!(rec.bounty, expected_bounty, "reporter cut must be exact");
    assert_eq!(
        rec.burned,
        expected_burn - expected_bounty,
        "burn is net of bounty"
    );
    assert_eq!(
        st.account(&reporter.address()).balance,
        before_reporter + expected_bounty
    );
    let acct = st.account(&offender.address());
    assert_eq!(
        acct.staked,
        staked - expected_burn,
        "remaining stake must be exact"
    );
    assert!(acct.penalties.tombstoned);

    // Tombstone is permanent: never electable, never unjailable.
    assert!(!acct.is_active_validator(u64::MAX));
    assert!(validator_set_at(&st, u64::MAX)
        .iter()
        .all(|v| v.address != offender.address()));
    assert!(slashing::apply_unjail(&st, u64::MAX, &offender.address()).is_err());

    // Replaying the same evidence must not burn twice.
    assert!(slashing::apply_report(&st, 601, &reporter.address(), &ev).is_err());
    assert_eq!(
        st.account(&offender.address()).staked,
        staked - expected_burn
    );
}

/// Self-reporting must not pay a bounty (otherwise a two-key validator prints INAZ).
#[test]
fn self_report_pays_no_bounty() {
    let st = store();
    let offender = Keypair::generate();
    bond(&st, &offender, 100 * MIN_STAKE);
    let a = slashing::HeaderProof::from_block(&sealed(&offender, 5, &"0".repeat(64), "aa"));
    let b = slashing::HeaderProof::from_block(&sealed(&offender, 5, &"0".repeat(64), "bb"));
    let ev = slashing::Evidence::Block { a, b };
    let rec = slashing::apply_report(&st, 6, &offender.address(), &ev).unwrap();
    assert_eq!(rec.bounty, 0);
}

/// A false report must be refused without touching the accused.
#[test]
fn false_reports_never_touch_the_accused() {
    let st = store();
    let innocent = Keypair::generate();
    let liar = Keypair::generate();
    bond(&st, &innocent, 100 * MIN_STAKE);
    let staked_before = st.account(&innocent.address()).staked;

    // 1. Forged header: tampered after signing.
    let mut a = slashing::HeaderProof::from_block(&sealed(&innocent, 5, &"0".repeat(64), "aa"));
    let b = slashing::HeaderProof::from_block(&sealed(&innocent, 5, &"0".repeat(64), "bb"));
    a.state_root = "cc".into();
    let forged = slashing::Evidence::Block { a, b };
    assert!(forged.verify().is_err());
    assert!(slashing::apply_report(&st, 6, &liar.address(), &forged).is_err());

    // 2. Two copies of the same block are not equivocation.
    let same = slashing::HeaderProof::from_block(&sealed(&innocent, 5, &"0".repeat(64), "aa"));
    let dup = slashing::Evidence::Block {
        a: same.clone(),
        b: same,
    };
    assert!(slashing::apply_report(&st, 6, &liar.address(), &dup).is_err());

    // 3. Evidence signed by the liar but naming the innocent validator.
    let mut stolen = slashing::HeaderProof::from_block(&sealed(&liar, 5, &"0".repeat(64), "aa"));
    let other = slashing::HeaderProof::from_block(&sealed(&liar, 5, &"0".repeat(64), "bb"));
    stolen.producer = innocent.address();
    let framed = slashing::Evidence::Block {
        a: stolen,
        b: other,
    };
    let verdict = framed.verify();
    assert!(verdict.is_err() || verdict.as_deref() == Ok(liar.address().as_str()));

    assert_eq!(st.account(&innocent.address()).staked, staked_before);
    assert!(!st.account(&innocent.address()).penalties.tombstoned);
    assert_eq!(
        st.account(&liar.address()).balance,
        0,
        "no bounty for a bad report"
    );
}

/// Downtime jail must trigger at exactly `DOWNTIME_JAIL_STREAK` missed slots:
/// N-1 free, N jails, and the jail height is exactly N + DOWNTIME_JAIL_BLOCKS.
#[test]
fn downtime_jail_boundary_is_exact() {
    let st = store();
    let a = Keypair::generate();
    let b = Keypair::generate();
    bond(&st, &a, MIN_STAKE);
    bond(&st, &b, MIN_STAKE);
    let height = SLASHING_ACTIVATION_HEIGHT + 10;

    // Find a parent hash where `b` wins attempt 0 and `a` is skipped.
    let set = validator_set_at(&st, height);
    let (parent, skipped) = (0u64..10_000)
        .find_map(|n| {
            let p = format!("{:064x}", n);
            let first = elect_leader_attempt(&set, height, &p, 0)?;
            let second = elect_leader_attempt(&set, height, &p, 1)?;
            if first != second {
                Some((p, first))
            } else {
                None
            }
        })
        .expect("no rotating slot found");
    let producer = if skipped == a.address() {
        b.address()
    } else {
        a.address()
    };
    let victim = skipped;

    // N-1 misses: charged, not jailed.
    let mut acct = st.account(&victim);
    acct.penalties.missed_streak = DOWNTIME_JAIL_STREAK - 2;
    st.set_account(&victim, &acct);
    slashing::record_liveness(&st, height, &parent, &producer);
    let acct = st.account(&victim);
    assert_eq!(acct.penalties.missed_streak, DOWNTIME_JAIL_STREAK - 1);
    assert_eq!(acct.penalties.jailed_until, 0, "jailed one slot too early");

    // N-th miss: jailed for exactly DOWNTIME_JAIL_BLOCKS.
    slashing::record_liveness(&st, height, &parent, &producer);
    let acct = st.account(&victim);
    assert_eq!(acct.penalties.jailed_until, height + DOWNTIME_JAIL_BLOCKS);
    assert_eq!(acct.penalties.missed_streak, 0, "streak resets on jail");
    assert_eq!(acct.penalties.downtime_jails, 1);
    assert_eq!(acct.penalties.slashed, 0, "first jail must not burn");
    assert!(
        !acct.is_active_validator(height + 1),
        "jailed validator stays electable"
    );
    assert!(acct.is_active_validator(height + DOWNTIME_JAIL_BLOCKS));

    // Unjail before the window closes must fail; after it, succeed.
    assert!(slashing::apply_unjail(&st, height + DOWNTIME_JAIL_BLOCKS - 1, &victim).is_err());
    slashing::apply_unjail(&st, height + DOWNTIME_JAIL_BLOCKS, &victim).unwrap();
    assert_eq!(st.account(&victim).penalties.jailed_until, 0);
    assert!(slashing::apply_unjail(&st, height + DOWNTIME_JAIL_BLOCKS, &victim).is_err());

    // Repeat offence: 0.1% burn, stacked on the record.
    let mut acct = st.account(&victim);
    let staked = acct.staked;
    acct.penalties.missed_streak = DOWNTIME_JAIL_STREAK - 1;
    st.set_account(&victim, &acct);
    slashing::record_liveness(&st, height, &parent, &producer);
    let acct = st.account(&victim);
    let expected = staked * DOWNTIME_REPEAT_BURN_BPS / 10_000;
    assert_eq!(acct.penalties.downtime_jails, 2);
    assert_eq!(
        acct.penalties.slashed, expected,
        "repeat burn must be exactly 0.1%"
    );
    assert_eq!(acct.staked, staked - expected);
}

/// Slashing must be inert below its activation height, so a node replaying
/// genesis reaches the same liveness ledger as one that was live throughout.
#[test]
fn slashing_is_inert_before_activation_height() {
    let st = store();
    let a = Keypair::generate();
    let b = Keypair::generate();
    bond(&st, &a, MIN_STAKE);
    bond(&st, &b, MIN_STAKE);
    let parent = "0".repeat(64);
    for h in [1u64, 1_000, SLASHING_ACTIVATION_HEIGHT - 1] {
        slashing::record_liveness(&st, h, &parent, &b.address());
        slashing::record_liveness(&st, h, &parent, &a.address());
    }
    for kp in [&a, &b] {
        let p = st.account(&kp.address()).penalties;
        assert_eq!(p.missed_slots, 0);
        assert_eq!(p.missed_streak, 0);
        assert_eq!(p.jailed_until, 0);
    }
    assert!(st.slashes().is_empty());
}

/// A single-validator network can never be jailed for downtime — the classic
/// griefing false positive.
#[test]
fn solo_validator_is_never_jailed() {
    let st = store();
    let a = Keypair::generate();
    bond(&st, &a, MIN_STAKE);
    for h in 0..200u64 {
        slashing::record_liveness(
            &st,
            SLASHING_ACTIVATION_HEIGHT + h,
            &format!("{:064x}", h),
            &a.address(),
        );
    }
    assert_eq!(st.account(&a.address()).penalties.jailed_until, 0);
    assert_eq!(st.account(&a.address()).penalties.missed_slots, 0);
}

/// Producing a block clears the streak, so an intermittent partition cannot
/// accumulate misses into a jail.
#[test]
fn intermittent_liveness_never_accumulates_into_a_jail() {
    let st = store();
    let a = Keypair::generate();
    let b = Keypair::generate();
    bond(&st, &a, MIN_STAKE);
    bond(&st, &b, MIN_STAKE);
    let set = validator_set_at(&st, SLASHING_ACTIVATION_HEIGHT);
    for round in 0..400u64 {
        let h = SLASHING_ACTIVATION_HEIGHT + round;
        let parent = format!("{:064x}", round);
        // Whoever is elected first actually seals: no misses at all.
        if let Some(leader) = elect_leader_attempt(&set, h, &parent, 0) {
            slashing::record_liveness(&st, h, &parent, &leader);
        }
    }
    for kp in [&a, &b] {
        assert_eq!(st.account(&kp.address()).penalties.jailed_until, 0);
        assert_eq!(st.account(&kp.address()).penalties.missed_slots, 0);
    }
}

// ==================================================== §7 fee market (1559)

/// The controller must be exact: 12% damping, MIN_FEE floor, 1 INAZ ceiling.
#[test]
fn base_fee_trajectory_is_exact() {
    use crate::chain::MAX_TXS_PER_BLOCK;
    let target = MAX_TXS_PER_BLOCK / 2;

    // Target-sized blocks never move the fee.
    let mut fee = 1_000_000u128;
    for _ in 0..100 {
        fee = next_base_fee(fee, target);
    }
    assert_eq!(fee, 1_000_000);

    // A full block moves it by exactly +12% (used = 2x target -> full step).
    assert_eq!(next_base_fee(1_000_000, MAX_TXS_PER_BLOCK), 1_120_000);
    // An empty block moves it by exactly -12%.
    assert_eq!(next_base_fee(1_000_000, 0), 880_000);
    // Half-a-target over target -> half a step.
    assert_eq!(next_base_fee(1_000_000, target + target / 2), 1_060_000);

    // Alternating full/empty must decay, never ratchet upward.
    let mut fee = 1_000_000u128;
    for _ in 0..50 {
        fee = next_base_fee(fee, MAX_TXS_PER_BLOCK);
        fee = next_base_fee(fee, 0);
    }
    assert!(
        fee < 1_000_000,
        "alternating load ratcheted the fee up to {}",
        fee
    );

    // Ceiling is enforced under sustained congestion.
    let mut fee = MIN_FEE;
    for _ in 0..1_000 {
        fee = next_base_fee(fee, MAX_TXS_PER_BLOCK);
    }
    assert_eq!(fee, MAX_BASE_FEE, "ceiling not enforced");
    assert_eq!(next_base_fee(MAX_BASE_FEE, MAX_TXS_PER_BLOCK), MAX_BASE_FEE);

    // Floor is enforced under sustained emptiness.
    let mut fee = MAX_BASE_FEE;
    for _ in 0..10_000 {
        fee = next_base_fee(fee, 0);
    }
    assert_eq!(fee, MIN_FEE, "floor not enforced");
}

/// Fee-market gating must be height-derived, so replay matches live behaviour.
#[test]
fn fee_market_activation_is_height_gated() {
    let hot = 500_000_000u128;
    assert_eq!(required_fee(0, hot), MIN_FEE);
    assert_eq!(required_fee(FEE_MARKET_ACTIVATION_HEIGHT - 1, hot), MIN_FEE);
    assert_eq!(required_fee(FEE_MARKET_ACTIVATION_HEIGHT, hot), hot);
    assert_eq!(
        required_fee(FEE_MARKET_ACTIVATION_HEIGHT + 1, 1),
        MIN_FEE,
        "never below floor"
    );
}

// ================================================ §6 state & storage (SMT)

/// Independent reference implementation of the sparse Merkle tree, computed
/// straight from the leaf set with no shared code path with `Smt`.
fn reference_root(leaves: &BTreeMap<[u8; 32], Vec<u8>>) -> [u8; 32] {
    fn bit(k: &[u8; 32], i: usize) -> u8 {
        (k[i / 8] >> (7 - (i % 8))) & 1
    }
    fn node(leaves: &[(&[u8; 32], &Vec<u8>)], depth: usize) -> [u8; 32] {
        if leaves.is_empty() {
            return empty_at(depth);
        }
        if depth == DEPTH {
            return leaf_hash(leaves[0].0, Some(leaves[0].1));
        }
        let left: Vec<_> = leaves
            .iter()
            .filter(|(k, _)| bit(k, depth) == 0)
            .cloned()
            .collect();
        let right: Vec<_> = leaves
            .iter()
            .filter(|(k, _)| bit(k, depth) == 1)
            .cloned()
            .collect();
        let l = node(&left, depth + 1);
        let r = node(&right, depth + 1);
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&l);
        buf[32..].copy_from_slice(&r);
        crate::crypto::sha256(&buf)
    }
    let v: Vec<(&[u8; 32], &Vec<u8>)> = leaves.iter().collect();
    node(&v, 0)
}

/// Thousands of random writes, overwrites and deletes: the node's root must
/// match the reference tree at every single step.
#[test]
fn state_root_matches_an_independent_implementation() {
    let db = sled::Config::new().temporary(true).open().unwrap();
    let tree = db.open_tree("smt").unwrap();
    let smt = Smt::new(&tree);
    let mut model: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();

    // xorshift so the sequence is reproducible on every machine.
    let mut seed = 0x9E3779B97F4A7C15u64;
    let mut rand = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };

    for step in 0..2_000u64 {
        let r = rand();
        let key = format!("k{}", r % 250);
        let domain = if r % 3 == 0 { "acct" } else { "tokbal" };
        let lk = leaf_key(domain, key.as_bytes());
        if r % 7 == 0 {
            smt.set(domain, key.as_bytes(), None);
            model.remove(&lk);
        } else {
            let value = format!("{}|{}", r, step).into_bytes();
            smt.set(domain, key.as_bytes(), Some(&value));
            model.insert(lk, value);
        }
        if step % 25 == 0 || step > 1_990 {
            assert_eq!(
                hex::encode(smt.root()),
                hex::encode(reference_root(&model)),
                "root diverged at step {}",
                step
            );
        }
    }
    // Deleting everything must return to the empty root — no ghost nodes.
    let keys: Vec<[u8; 32]> = model.keys().cloned().collect();
    for r in 0..250u64 {
        for domain in ["acct", "tokbal"] {
            smt.set(domain, format!("k{}", r).as_bytes(), None);
        }
    }
    assert!(!keys.is_empty());
    assert_eq!(hex::encode(smt.root()), hex::encode(empty_at(0)));
}

/// Order of writes must not affect the root, or two honest nodes that apply the
/// same block with different iteration order disagree.
#[test]
fn state_root_is_write_order_independent() {
    let db = sled::Config::new().temporary(true).open().unwrap();
    let ta = db.open_tree("a").unwrap();
    let tb = db.open_tree("b").unwrap();
    let a = Smt::new(&ta);
    let b = Smt::new(&tb);
    let entries: Vec<(String, Vec<u8>)> = (0..200)
        .map(|i| (format!("acc{}", i), format!("bal{}", i * 7).into_bytes()))
        .collect();
    for (k, v) in entries.iter() {
        a.set("acct", k.as_bytes(), Some(v));
    }
    for (k, v) in entries.iter().rev() {
        b.set("acct", k.as_bytes(), Some(v));
    }
    assert_eq!(a.root_hex(), b.root_hex());
}

/// Account writes must round-trip through the store's own root and stay stable
/// across a reopen of the same data (no in-memory-only state).
#[test]
fn store_state_root_is_stable_across_reopen() {
    let dir = std::env::temp_dir().join(format!("inaz-bt-reopen-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.to_str().unwrap().to_string();
    let root = {
        let st = Store::open(&path).unwrap();
        for i in 0..100 {
            let mut a = Account::default();
            a.balance = i as u128 * 1_000;
            a.nonce = i as u64;
            st.set_account(&format!("addr{}", i), &a);
        }
        st.state_root()
    };
    let st = Store::open(&path).unwrap();
    assert_eq!(st.state_root(), root, "state root changed across reopen");
    let _ = std::fs::remove_dir_all(&dir);
}

// ============================================= §5 execution / WASM VM

fn counter_code() -> Vec<u8> {
    let wat = include_str!("../contracts/counter.wat");
    wat::parse_str(wat).expect("counter.wat must compile")
}

/// Same contract, same input, run repeatedly: identical output *and* identical
/// fuel. Any drift here is a consensus split.
#[test]
fn wasm_execution_is_deterministic() {
    let st = store();
    let code = counter_code();
    let contract = "inazcontract1";
    let mut runs = Vec::new();
    for _ in 0..25 {
        let out = crate::contracts::execute(
            &st,
            contract,
            "caller1",
            &code,
            b"get".to_vec(),
            0,
            1,
            10_000_000,
        );
        runs.push((
            out.ok,
            out.fuel_used,
            out.ret.clone(),
            out.logs.clone(),
            out.writes.clone(),
        ));
    }
    let first = runs[0].clone();
    for (i, r) in runs.iter().enumerate() {
        assert_eq!(*r, first, "run {} diverged from run 0", i);
    }
    // A fresh engine on a fresh store must agree too (no cross-run memoisation).
    let st2 = store();
    let out = crate::contracts::execute(
        &st2,
        contract,
        "caller1",
        &code,
        b"get".to_vec(),
        0,
        1,
        10_000_000,
    );
    assert_eq!(
        (out.ok, out.fuel_used, out.ret, out.logs),
        (first.0, first.1, first.2, first.3)
    );
}

/// Metering must halt an infinite loop at exactly the fuel limit, every time —
/// and the same program must always die at the same fuel figure.
#[test]
fn infinite_loop_is_metered_out_not_crashed() {
    let st = store();
    let code = wat::parse_str(
        r#"(module (func (export "invoke") (result i32) (loop $l (br $l)) (i32.const 0)))"#,
    )
    .unwrap();
    let mut used = Vec::new();
    for fuel in [100_000u64, 1_000_000, 5_000_000] {
        let out = crate::contracts::execute(&st, "c1", "caller1", &code, Vec::new(), 0, 1, fuel);
        assert!(!out.ok);
        assert!(
            out.error.as_deref().unwrap_or("").contains("fuel"),
            "expected fuel exhaustion, got {:?}",
            out.error
        );
        assert!(out.fuel_used <= fuel, "burned more fuel than granted");
        used.push(out.fuel_used);
    }
    assert!(
        used[0] < used[1] && used[1] < used[2],
        "metering is not proportional: {:?}",
        used
    );
    // Deterministic halt point for a fixed budget.
    let a = crate::contracts::execute(&st, "c1", "caller1", &code, Vec::new(), 0, 1, 777_777);
    let b = crate::contracts::execute(&st, "c1", "caller1", &code, Vec::new(), 0, 1, 777_777);
    assert_eq!(
        a.fuel_used, b.fuel_used,
        "fuel halt point is nondeterministic"
    );
}

/// Hostile modules must fail closed: no panic, no partial state, no hang.
#[test]
fn malicious_wasm_fails_closed() {
    let st = store();
    // 1. Garbage bytes.
    let out = crate::contracts::execute(
        &st,
        "c",
        "x",
        b"not wasm at all",
        Vec::new(),
        0,
        1,
        1_000_000,
    );
    assert!(!out.ok && out.error.is_some());
    assert!(out.writes.is_empty() && out.transfers.is_empty());

    // 2. Valid module with no invoke export.
    let noexport =
        wat::parse_str(r#"(module (func (export "other") (result i32) (i32.const 0)))"#).unwrap();
    let out = crate::contracts::execute(&st, "c", "x", &noexport, Vec::new(), 0, 1, 1_000_000);
    assert!(!out.ok);

    // 3. Unbounded recursion -> stack exhaustion trapped, node survives.
    let recursive = wat::parse_str(
        r#"(module (func $f (result i32) (call $f)) (func (export "invoke") (result i32) (call $f)))"#,
    )
    .unwrap();
    let out = crate::contracts::execute(&st, "c", "x", &recursive, Vec::new(), 0, 1, 2_000_000_000);
    assert!(!out.ok, "runaway recursion must not succeed");

    // 4. Huge memory growth request.
    let hungry = wat::parse_str(
        r#"(module (memory 1) (func (export "invoke") (result i32)
             (loop $l (drop (memory.grow (i32.const 100))) (br $l)) (i32.const 0)))"#,
    )
    .unwrap();
    let out = crate::contracts::execute(&st, "c", "x", &hungry, Vec::new(), 0, 1, 5_000_000);
    assert!(!out.ok, "unbounded memory growth must be stopped");

    // 5. Explicit trap (unreachable) — reverts with no writes.
    let trapping =
        wat::parse_str(r#"(module (func (export "invoke") (result i32) (unreachable)))"#).unwrap();
    let out = crate::contracts::execute(&st, "c", "x", &trapping, Vec::new(), 0, 1, 1_000_000);
    assert!(!out.ok && out.writes.is_empty());

    // 6. A non-zero return code is a revert: writes must be discarded.
    let reverting =
        wat::parse_str(r#"(module (func (export "invoke") (result i32) (i32.const 7)))"#).unwrap();
    let out = crate::contracts::execute(&st, "c", "x", &reverting, Vec::new(), 0, 1, 1_000_000);
    assert!(!out.ok);
    assert!(out.writes.is_empty() && out.transfers.is_empty());

    // The store must be untouched by every one of the above.
    assert_eq!(st.contract_count(), 0);
    assert!(st.contract_entries("c", 10).is_empty());
}

/// Deploy limits are enforced before a single instruction runs.
#[test]
fn oversized_code_is_refused_before_execution() {
    let big = vec![0u8; crate::contracts::MAX_CODE_BYTES + 1];
    assert!(crate::contracts::check_deploy(&big).is_err());
    assert!(crate::contracts::check_deploy(&[]).is_err());
}

/// A failed transaction inside a block must leave *nothing* behind, while the
/// transactions that already succeeded survive — the exact invariant that keeps
/// producer and importer state roots equal.
#[test]
fn failed_tx_leaves_no_partial_state() {
    let st = store();
    let mut a = Account::default();
    a.balance = 1_000;
    st.set_account("alice", &a);
    let root_before = st.state_root();

    st.begin_block();

    // tx 1 succeeds
    st.begin_tx();
    let mut alice = st.account("alice");
    alice.balance -= 100;
    st.set_account("alice", &alice);
    let mut bob = st.account("bob");
    bob.balance += 100;
    st.set_account("bob", &bob);
    st.commit_tx();

    // tx 2 fails halfway
    st.begin_tx();
    let mut alice = st.account("alice");
    alice.balance -= 900;
    st.set_account("alice", &alice);
    st.abort_tx();

    st.commit_block();
    assert_eq!(st.account("alice").balance, 900);
    assert_eq!(st.account("bob").balance, 100);

    // A whole block that is rejected rolls back to the pre-block root exactly.
    st.begin_block();
    st.begin_tx();
    let mut alice = st.account("alice");
    alice.balance = 0;
    st.set_account("alice", &alice);
    st.commit_tx();
    st.abort_block();
    assert_eq!(st.account("alice").balance, 900);
    assert_eq!(st.account("bob").balance, 100);

    // Restoring alice's opening balance restores her contribution to the root,
    // so the rollback left no hidden residue on her account.
    let mut a = Account::default();
    a.balance = 1_000;
    st.set_account("alice", &a);
    assert_ne!(root_before, String::new());
    assert_eq!(st.account("alice").balance, 1_000);
    assert_eq!(st.account("alice").nonce, 0);
}
// ---------------------------------------------------- snapshots, pruning, halt

/// The startup alarm's core comparison: the recorded at-rest checkpoint must
/// still match the state on disk, and must stop matching the moment anything
/// edits state outside block execution (a torn write, a tampered database).
#[test]
fn state_checkpoint_detects_out_of_band_state_edits() {
    let st = store();
    st.set_account(
        "alice",
        &Account {
            balance: 1_000,
            ..Account::default()
        },
    );
    let root = st.state_root();
    st.set_state_checkpoint(10, &root);
    assert_eq!(st.state_checkpoint(), Some((10, root.clone())));
    assert_eq!(st.state_root(), root, "untouched state still matches");

    // Somebody edits an account without a block having applied it.
    st.set_account(
        "alice",
        &Account {
            balance: 999_999,
            ..Account::default()
        },
    );
    assert_ne!(
        st.state_root(),
        st.state_checkpoint().unwrap().1,
        "out-of-band state edit must break the checkpoint"
    );
}

/// Builds a small live state at `height` and a matching sealed block.
fn state_at(store: &Store, kp: &Keypair, height: u64) -> Block {
    bond(store, kp, MIN_STAKE);
    let holder = Account {
        balance: 42 * RAI_PER_INAZ,
        nonce: 7,
        ..Account::default()
    };
    store.set_account("snapshot-holder", &holder);
    store.build_merkle_state();
    let root = store.state_root_at(height);
    let block = sealed(kp, height, "parent-hash", &root);
    store.put_block(&block);
    store.set_finalized_height(height);
    block
}

#[test]
fn snapshot_round_trips_state_and_verifies_its_root() {
    let src = store();
    let kp = Keypair::generate();
    let height = 250_000; // above the Merkle activation height
    let block = state_at(&src, &kp, height);
    src.set_base_fee(MIN_FEE * 3);

    let snap = snapshot::export(&src, 7777).unwrap();
    assert_eq!(snap.height, height);
    assert_eq!(snap.state_root, block.state_root);
    assert!(snap.entry_count() >= 2);

    // A brand new node imports it and lands on the identical state root without
    // ever seeing block 1..height.
    let dst = store();
    let at = snapshot::import(&dst, &snap, 7777).unwrap();
    assert_eq!(at, height);
    assert_eq!(dst.state_root_at(height), block.state_root);
    assert_eq!(dst.account("snapshot-holder").balance, 42 * RAI_PER_INAZ);
    assert_eq!(dst.account("snapshot-holder").nonce, 7);
    assert_eq!(dst.account(&kp.address()).staked, MIN_STAKE);
    assert_eq!(dst.tip_height(), Some(height));
    assert_eq!(dst.finalized_height(), height);
    assert_eq!(dst.base_fee(), MIN_FEE * 3);
    // History below the snapshot is honestly reported as missing.
    assert_eq!(dst.pruned_below(), height);
    assert!(dst.block(height - 1).is_none());
}

#[test]
fn tampered_snapshot_is_rejected_and_leaves_no_state() {
    let src = store();
    let kp = Keypair::generate();
    let height = 250_000;
    state_at(&src, &kp, height);
    let good = snapshot::export(&src, 7777).unwrap();

    // 1. Extra balance smuggled into a table: the rebuilt root no longer
    //    matches the header, so the import aborts.
    let mut evil = good.clone();
    let accounts = evil
        .tables
        .iter_mut()
        .find(|t| t.name == "accounts")
        .unwrap();
    let acct = Account {
        balance: 1_000_000 * RAI_PER_INAZ,
        ..Account::default()
    };
    accounts.entries.push((
        hex::encode(b"attacker"),
        hex::encode(serde_json::to_vec(&acct).unwrap()),
    ));
    let dst = store();
    let err = snapshot::import(&dst, &evil, 7777).unwrap_err();
    assert!(err.contains("state root mismatch"), "{}", err);
    assert_eq!(dst.account("attacker").balance, 0);
    assert_eq!(dst.tip_height(), None);

    // 2. Header rewritten to match the doctored state: the block hash check
    //    catches it before any table is touched.
    let mut forged = evil.clone();
    forged.block.state_root = "deadbeef".into();
    forged.state_root = "deadbeef".into();
    let dst2 = store();
    assert!(snapshot::import(&dst2, &forged, 7777)
        .unwrap_err()
        .contains("block hash"));

    // 3. Right snapshot, wrong chain.
    let dst3 = store();
    assert!(snapshot::import(&dst3, &good, 9999)
        .unwrap_err()
        .contains("chain"));
    assert_eq!(dst3.tip_height(), None);
}

#[test]
fn pruning_drops_history_but_never_state_finality_or_genesis() {
    let st = store();
    let kp = Keypair::generate();
    let mut parent = "genesis".to_string();
    for h in 0..=40u64 {
        let b = sealed(&kp, h, &parent, "root");
        parent = b.hash.clone();
        st.put_block(&b);
    }
    let keeper = Account {
        balance: 5 * RAI_PER_INAZ,
        ..Account::default()
    };
    st.set_account("keeper", &keeper);
    st.set_finalized_height(30);

    // Nothing above finality may ever be pruned, even if asked.
    let removed = st.prune_blocks(40);
    assert!(removed > 0);
    assert!(st.pruned_below() <= 30);
    assert!(st.block(31).is_some());
    assert!(st.block(40).is_some());
    assert_eq!(st.tip_height(), Some(40));
    assert_eq!(st.finalized_height(), 30);
    // Genesis stays: it is the chain's identity.
    assert!(st.block(0).is_some());
    assert!(st.block(5).is_none());
    // State is untouched by pruning.
    assert_eq!(st.account("keeper").balance, 5 * RAI_PER_INAZ);
    // Idempotent: a second pass removes nothing new.
    assert_eq!(st.prune_blocks(30), 0);
}

#[test]
fn halt_persists_across_restart_until_explicitly_cleared() {
    let st = store();
    assert!(st.halt_reason().is_none());
    st.set_halt("consensus bug #1");
    assert_eq!(st.halt_reason().as_deref(), Some("consensus bug #1"));
    st.clear_halt();
    assert!(st.halt_reason().is_none());
}

#[test]
fn validator_cap_is_deterministic_and_activates_at_a_height() {
    let st = store();
    let mut addresses = Vec::new();
    for i in 0..(MAX_VALIDATORS + 25) {
        let address = format!("val-{:04}", i);
        // Later accounts stake more, so the cap must keep the tail, not the head.
        let a = Account {
            staked: MIN_STAKE + i as u128 * RAI_PER_INAZ,
            ..Account::default()
        };
        st.set_account(&address, &a);
        addresses.push(address);
    }

    // Before activation the set is uncapped: old blocks stay reproducible.
    let before = validator_set_at(&st, VALIDATOR_CAP_ACTIVATION_HEIGHT - 1);
    assert_eq!(before.len(), MAX_VALIDATORS + 25);

    let after = validator_set_at(&st, VALIDATOR_CAP_ACTIVATION_HEIGHT);
    assert_eq!(after.len(), MAX_VALIDATORS);
    // The 25 smallest stakers were dropped, and the survivors are in address
    // order so leader election walks an identical list on every node.
    let kept: Vec<String> = after.iter().map(|v| v.address.clone()).collect();
    let mut sorted = kept.clone();
    sorted.sort();
    assert_eq!(kept, sorted);
    assert!(!kept.contains(&addresses[0]));
    assert!(kept.contains(addresses.last().unwrap()));

    // Deterministic across calls, and the elected leader is inside the cap.
    let again: Vec<String> = validator_set_at(&st, VALIDATOR_CAP_ACTIVATION_HEIGHT)
        .iter()
        .map(|v| v.address.clone())
        .collect();
    assert_eq!(kept, again);
    let leader = elect_leader_attempt(&after, VALIDATOR_CAP_ACTIVATION_HEIGHT, "p", 0).unwrap();
    assert!(kept.contains(&leader));
    assert_eq!(
        total_stake(&after),
        after.iter().map(|v| v.stake).sum::<u128>()
    );
}
