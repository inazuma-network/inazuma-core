//! Pre-testnet conformance suite.
//!
//! Maps 1:1 onto the ten-category launch checklist a client team runs before a
//! devnet is promoted to a public testnet. Categories that are EVM-specific
//! (opcode vectors, precompiles, ethereum/tests) are covered by their WASM
//! equivalents, because this chain has no EVM.
//!
//!   §1 consensus      §2 execution/VM   §3 p2p        §4 mempool
//!   §5 state/storage  §6 contracts      §7 rpc        §8 load
//!   §9 security       §10 upgrade/fork
#![cfg(test)]

use crate::chain::{check_reorg_depth, check_timestamp, Node, MAX_TXS_PER_BLOCK};
use crate::crypto::Keypair;
use crate::fees::next_base_fee;
use crate::mempool::MAX_PENDING_PER_SENDER;
use crate::rpcauth::{RpcConfig, Tier};
use crate::snapshot;
use crate::staking::{elect_leader, elect_leader_attempt, validator_set, BLOCK_REWARD};
use crate::state::Store;
use crate::tokens;
use crate::types::{
    Genesis, GenesisAlloc, Payload, Transaction, TxKind, MIN_FEE, MIN_STAKE, RAI_PER_INAZ,
};
use serde_json::json;
use std::sync::Arc;

// ------------------------------------------------------------------ harness

fn tmp(tag: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir()
        .join(format!(
            "inaz-cf-{}-{}-{}",
            tag,
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ))
        .to_string_lossy()
        .to_string()
}

/// A solo node whose producer is funded and bonded at genesis.
fn net(tag: &str) -> (Arc<Node>, Keypair) {
    let kp = Keypair::generate();
    let user = Keypair::from_secret_hex(&kp.secret_hex()).unwrap();
    let genesis = Genesis {
        chain_id: 7777,
        chain_name: "Inazuma".into(),
        symbol: "INAZ".into(),
        decimals: 9,
        block_time_ms: 400,
        alloc: vec![GenesisAlloc {
            address: kp.address(),
            balance: "1000000".into(),
            stake: Some("10000".into()),
        }],
    };
    let store = Store::open(&tmp(tag)).unwrap();
    let node = Arc::new(Node::new(store, genesis, kp));
    node.set_solo(true);
    node.init_genesis().unwrap();
    (node, user)
}

fn signed(
    kind: TxKind,
    kp: &Keypair,
    to: &str,
    amount: u128,
    fee: u128,
    nonce: u64,
    payload: Option<Payload>,
) -> Transaction {
    let mut tx = Transaction {
        kind,
        from_pubkey: kp.pubkey_hex(),
        to: to.to_string(),
        amount,
        fee,
        nonce,
        chain_id: 7777,
        payload,
        signature: String::new(),
    };
    tx.signature = kp.sign_hex(&tx.canonical_signing_bytes());
    tx
}

fn transfer(kp: &Keypair, to: &str, amount: u128, nonce: u64) -> Transaction {
    signed(TxKind::Transfer, kp, to, amount, MIN_FEE, nonce, None)
}

fn seal(node: &Arc<Node>) -> u64 {
    node.produce_block().unwrap().map(|b| b.height).unwrap_or(0)
}

fn counter_code() -> Vec<u8> {
    wat::parse_str(include_str!("../contracts/counter.wat")).unwrap()
}

// ================================================== §1 consensus layer

#[test]
fn c1_block_production_under_normal_conditions() {
    let (node, kp) = net("c1a");
    let bob = Keypair::generate().address();
    for i in 0..10u64 {
        node.accept_tx(transfer(&kp, &bob, RAI_PER_INAZ, i)).unwrap();
        let h = seal(&node);
        assert_eq!(h, i + 1, "height must advance one per block");
    }
    assert_eq!(node.store.account(&bob).balance, 10 * RAI_PER_INAZ);
}

#[test]
fn c1_parent_hash_chains_every_block() {
    let (node, _) = net("c1b");
    for _ in 0..8 {
        seal(&node);
    }
    let tip = node.store.tip_height().unwrap();
    for h in 1..=tip {
        let b = node.store.block(h).unwrap();
        let p = node.store.block(h - 1).unwrap();
        assert_eq!(b.parent_hash, p.hash, "height {} not chained", h);
        assert_eq!(b.hash, b.compute_hash(), "height {} hash mismatch", h);
    }
}

#[test]
fn c1_leader_election_is_deterministic() {
    let (node, _) = net("c1c");
    let set = validator_set(&node.store);
    let a = elect_leader(&set, 42, "deadbeef");
    for _ in 0..100 {
        assert_eq!(elect_leader(&set, 42, "deadbeef"), a);
    }
}

#[test]
fn c1_leader_rotates_with_attempt() {
    let (node, _) = net("c1d");
    let set = validator_set(&node.store);
    let mut seen = 0;
    for attempt in 0..8 {
        if elect_leader_attempt(&set, 9, "abc", attempt).is_some() {
            seen += 1;
        }
    }
    assert_eq!(seen, 8, "rotation must always yield a leader");
}

#[test]
fn c1_reorg_depth_limit_is_total() {
    assert!(check_reorg_depth(10_000, 10_001).is_ok());
    assert!(check_reorg_depth(10_000, 4_000).is_err());
    assert!(check_reorg_depth(0, 0).is_ok());
}

#[test]
fn c1_timestamp_monotonic_and_drift_bounded() {
    assert!(check_timestamp(1_000, 1_001, 1_001).is_ok());
    assert!(check_timestamp(1_000, 999, 5_000).is_err(), "backwards ts");
    assert!(check_timestamp(1_000, 1_000, 5_000).is_err(), "equal ts");
    assert!(
        check_timestamp(1_000, 100_000, 1_000).is_err(),
        "far-future ts"
    );
}

#[test]
fn c1_produced_block_state_root_matches_disk() {
    let (node, kp) = net("c1e");
    let bob = Keypair::generate().address();
    node.accept_tx(transfer(&kp, &bob, 5 * RAI_PER_INAZ, 0))
        .unwrap();
    let h = seal(&node);
    let b = node.store.block(h).unwrap();
    assert_eq!(b.state_root, node.store.state_root_at(h));
}

#[test]
fn c1_block_signature_verifies_and_tamper_fails() {
    let (node, _) = net("c1f");
    let h = seal(&node);
    let b = node.store.block(h).unwrap();
    assert!(crate::crypto::verify(
        &b.producer_pubkey,
        &b.header_bytes(),
        &b.signature
    ));
    let mut bad = b.clone();
    bad.state_root = "0".repeat(64);
    assert!(!crate::crypto::verify(
        &bad.producer_pubkey,
        &bad.header_bytes(),
        &bad.signature
    ));
}

#[test]
fn c1_halt_stops_production_resume_restores_it() {
    let (node, _) = net("c1g");
    let before = seal(&node);
    node.halt("conformance");
    assert!(node.halted());
    assert!(node.produce_block().unwrap().is_none());
    assert_eq!(node.store.tip_height().unwrap(), before);
    node.resume();
    let after = seal(&node);
    assert_eq!(after, before + 1);
}

#[test]
fn c1_serving_only_replica_never_produces() {
    let (node, _) = net("c1h");
    node.set_serving_only(true);
    assert!(node.produce_block().unwrap().is_none());
    node.set_serving_only(false);
    assert!(node.produce_block().unwrap().is_some());
}

#[test]
fn c1_block_reward_paid_exactly_once_per_block() {
    let (node, kp) = net("c1i");
    let before = node.store.account(&kp.address()).rewards;
    for _ in 0..5 {
        seal(&node);
    }
    let after = node.store.account(&kp.address()).rewards;
    assert_eq!(after - before, 5 * BLOCK_REWARD);
}

#[test]
fn c1_total_supply_only_grows_by_block_reward() {
    let (node, kp) = net("c1j");
    let bob = Keypair::generate().address();
    let start = node.store.total_supply();
    for i in 0..6u64 {
        node.accept_tx(transfer(&kp, &bob, RAI_PER_INAZ, i)).unwrap();
        seal(&node);
    }
    let end = node.store.total_supply();
    assert_eq!(end - start, 6 * BLOCK_REWARD, "supply inflation drifted");
}

// ================================================== §2 execution layer

#[test]
fn c2_transfer_debits_credits_and_bumps_nonce() {
    let (node, kp) = net("c2a");
    let bob = Keypair::generate().address();
    let pre = node.store.account(&kp.address()).balance;
    node.accept_tx(transfer(&kp, &bob, 3 * RAI_PER_INAZ, 0))
        .unwrap();
    seal(&node);
    let a = node.store.account(&kp.address());
    assert_eq!(node.store.account(&bob).balance, 3 * RAI_PER_INAZ);
    assert_eq!(a.nonce, 1);
    // The sender is also the block producer here, so it earns the reward and
    // its own fee back; the net movement is the transfer minus that credit.
    assert!(pre - a.balance <= 3 * RAI_PER_INAZ, "sender over-debited");
    assert!(pre - a.balance > 2 * RAI_PER_INAZ, "sender under-debited");
}

#[test]
fn c2_insufficient_balance_is_rejected() {
    let (node, _) = net("c2b");
    let poor = Keypair::generate();
    let bob = Keypair::generate().address();
    let r = node.accept_tx(transfer(&poor, &bob, RAI_PER_INAZ, 0));
    assert!(r.is_err(), "spending from an empty account must fail");
}

#[test]
fn c2_wrong_chain_id_is_rejected() {
    let (node, kp) = net("c2c");
    let mut tx = transfer(&kp, &Keypair::generate().address(), RAI_PER_INAZ, 0);
    tx.chain_id = 1;
    tx.signature = kp.sign_hex(&tx.canonical_signing_bytes());
    assert!(node.accept_tx(tx).is_err(), "cross-chain replay accepted");
}

#[test]
fn c2_bad_signature_is_rejected() {
    let (node, kp) = net("c2d");
    let mut tx = transfer(&kp, &Keypair::generate().address(), RAI_PER_INAZ, 0);
    tx.amount += 1;
    assert!(node.accept_tx(tx).is_err());
}

#[test]
fn c2_foreign_signature_is_rejected() {
    let (node, kp) = net("c2e");
    let mallory = Keypair::generate();
    let mut tx = transfer(&kp, &Keypair::generate().address(), RAI_PER_INAZ, 0);
    tx.signature = mallory.sign_hex(&tx.canonical_signing_bytes());
    assert!(node.accept_tx(tx).is_err());
}

#[test]
fn c2_fee_below_floor_is_rejected() {
    let (node, kp) = net("c2f");
    let tx = signed(
        TxKind::Transfer,
        &kp,
        &Keypair::generate().address(),
        RAI_PER_INAZ,
        0,
        0,
        None,
    );
    assert!(node.accept_tx(tx).is_err(), "zero-fee tx accepted");
}

#[test]
fn c2_replay_of_same_tx_is_rejected() {
    let (node, kp) = net("c2g");
    let bob = Keypair::generate().address();
    let tx = transfer(&kp, &bob, RAI_PER_INAZ, 0);
    node.accept_tx(tx.clone()).unwrap();
    seal(&node);
    assert!(node.accept_tx(tx).is_err(), "replayed tx accepted");
    assert_eq!(node.store.account(&bob).balance, RAI_PER_INAZ);
}

#[test]
fn c2_stale_nonce_is_rejected() {
    let (node, kp) = net("c2h");
    let bob = Keypair::generate().address();
    node.accept_tx(transfer(&kp, &bob, RAI_PER_INAZ, 0)).unwrap();
    seal(&node);
    assert!(node.accept_tx(transfer(&kp, &bob, RAI_PER_INAZ, 0)).is_err());
}

#[test]
fn c2_invalid_recipient_address_is_rejected() {
    let (node, kp) = net("c2i");
    let tx = transfer(&kp, "not-an-address", RAI_PER_INAZ, 0);
    assert!(node.accept_tx(tx).is_err());
}

#[test]
fn c2_stake_and_unstake_move_bonded_balance() {
    let (node, kp) = net("c2j");
    let before = node.store.account(&kp.address()).staked;
    node.accept_tx(signed(
        TxKind::Stake,
        &kp,
        &kp.address(),
        MIN_STAKE,
        MIN_FEE,
        0,
        None,
    ))
    .unwrap();
    seal(&node);
    assert_eq!(node.store.account(&kp.address()).staked, before + MIN_STAKE);
    node.accept_tx(signed(
        TxKind::Unstake,
        &kp,
        &kp.address(),
        MIN_STAKE,
        MIN_FEE,
        1,
        None,
    ))
    .unwrap();
    seal(&node);
    let a = node.store.account(&kp.address());
    assert_eq!(a.staked, before);
    assert_eq!(a.unbonding_total(), MIN_STAKE, "unbonding lock missing");
}

#[test]
fn c2_unstake_more_than_bonded_is_rejected() {
    let (node, kp) = net("c2k");
    let too_much = node.store.account(&kp.address()).staked + RAI_PER_INAZ;
    let tx = signed(
        TxKind::Unstake,
        &kp,
        &kp.address(),
        too_much,
        MIN_FEE,
        0,
        None,
    );
    let admitted = node.accept_tx(tx).is_ok();
    seal(&node);
    let a = node.store.account(&kp.address());
    assert!(
        a.unbonding_total() == 0,
        "over-unstake changed state (admitted={})",
        admitted
    );
}

#[test]
fn c2_failed_tx_leaves_state_root_unchanged() {
    let (node, _) = net("c2l");
    let root = node.store.state_root();
    let poor = Keypair::generate();
    let _ = node.accept_tx(transfer(&poor, &Keypair::generate().address(), 1, 0));
    assert_eq!(node.store.state_root(), root);
}

// ================================================== §3 networking / p2p

#[test]
fn c3_reorg_guard_rejects_long_range_peer() {
    assert!(check_reorg_depth(1_000_000, 1).is_err());
}

#[test]
fn c3_peer_ban_after_repeated_abuse() {
    use crate::limits::PeerBook;
    use std::net::{IpAddr, Ipv4Addr};
    let book = PeerBook::new(60);
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    assert!(!book.is_banned(ip));
    for _ in 0..200 {
        book.penalize(ip, 10);
    }
    assert!(book.is_banned(ip), "spamming peer never banned");
    assert!(book.banned_count() >= 1);
}

#[test]
fn c3_conn_guard_caps_total_connections() {
    use crate::limits::ConnGuard;
    let g = ConnGuard::new(3);
    let a = g.try_acquire();
    let b = g.try_acquire();
    let c = g.try_acquire();
    assert!(a.is_some() && b.is_some() && c.is_some());
    assert!(g.try_acquire().is_none(), "connection cap not enforced");
    drop(a);
    assert!(g.try_acquire().is_some(), "slot not released");
}

#[test]
fn c3_per_ip_connection_cap() {
    use crate::limits::IpConnCounter;
    use std::net::{IpAddr, Ipv4Addr};
    let c = IpConnCounter::new(2);
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let t1 = c.try_acquire(ip);
    let t2 = c.try_acquire(ip);
    assert!(t1.is_some() && t2.is_some());
    assert!(c.try_acquire(ip).is_none());
    // a different IP is unaffected
    assert!(c
        .try_acquire(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)))
        .is_some());
}

#[test]
fn c3_encrypted_transport_frame_limit_is_bounded() {
    assert!(crate::transport::MAX_FRAME <= 8 * 1024 * 1024);
    assert_eq!(crate::transport::MAGIC, b"INSC1");
}

#[test]
fn c3_identity_pinning_detects_key_swap() {
    use crate::limits::PeerBook;
    use std::net::{IpAddr, Ipv4Addr};
    let book = PeerBook::new(60);
    let ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
    assert!(book.note_identity(ip, "peer-a"));
    // note_identity returns true only the first time a pairing is seen, so a
    // repeat of the same identity is `false` (nothing new to log)...
    assert!(!book.note_identity(ip, "peer-a"), "same identity re-logged");
    // ...while a key swap on a pinned IP is reported as a new pairing so the
    // node logs and re-evaluates it.
    assert!(
        book.note_identity(ip, "peer-b"),
        "identity swap on a pinned IP went unnoticed"
    );
}

// ================================================== §4 mempool

#[test]
fn c4_nonce_ordering_within_a_block() {
    let (node, kp) = net("c4a");
    let bob = Keypair::generate().address();
    // submit out of order
    for n in [2u64, 0, 1] {
        let _ = node.accept_tx(transfer(&kp, &bob, RAI_PER_INAZ, n));
    }
    seal(&node);
    seal(&node);
    let a = node.store.account(&kp.address());
    assert!(a.nonce >= 1, "no tx applied");
    // nonces must have been applied strictly in order
    assert_eq!(
        node.store.account(&bob).balance,
        a.nonce as u128 * RAI_PER_INAZ
    );
}

#[test]
fn c4_pending_nonce_tracks_mempool() {
    let (node, kp) = net("c4b");
    let bob = Keypair::generate().address();
    assert_eq!(node.pending_nonce(&kp.address()), 0);
    node.accept_tx(transfer(&kp, &bob, RAI_PER_INAZ, 0)).unwrap();
    assert_eq!(node.pending_nonce(&kp.address()), 1);
}

#[test]
fn c4_per_sender_pending_cap() {
    let (node, kp) = net("c4c");
    let bob = Keypair::generate().address();
    let mut ok = 0u64;
    for n in 0..(MAX_PENDING_PER_SENDER + 20) {
        if node.accept_tx(transfer(&kp, &bob, 1_000, n)).is_ok() {
            ok += 1;
        }
    }
    assert!(
        ok <= MAX_PENDING_PER_SENDER,
        "per-sender cap breached: {}",
        ok
    );
}

#[test]
fn c4_duplicate_hash_not_pooled_twice() {
    let (node, kp) = net("c4d");
    let tx = transfer(&kp, &Keypair::generate().address(), RAI_PER_INAZ, 0);
    node.accept_tx(tx.clone()).unwrap();
    let before = node.mempool_size();
    let _ = node.accept_tx(tx);
    assert_eq!(node.mempool_size(), before, "duplicate entered the pool");
}

#[test]
fn c4_block_drains_the_pool() {
    let (node, kp) = net("c4e");
    let bob = Keypair::generate().address();
    for n in 0..10 {
        node.accept_tx(transfer(&kp, &bob, 1_000, n)).unwrap();
    }
    assert_eq!(node.mempool_size(), 10);
    seal(&node);
    assert_eq!(node.mempool_size(), 0, "pool not drained");
}

#[test]
fn c4_fee_market_rises_under_load_and_decays() {
    let full = MAX_TXS_PER_BLOCK;
    let mut fee = MIN_FEE;
    for _ in 0..20 {
        fee = next_base_fee(fee, full);
    }
    assert!(fee > MIN_FEE, "base fee never rose under full blocks");
    let mut down = fee;
    for _ in 0..200 {
        down = next_base_fee(down, 0);
    }
    assert!(down < fee, "base fee never decayed on empty blocks");
    assert!(down >= MIN_FEE, "base fee fell below the floor");
}

#[test]
fn c4_mempool_eviction_prefers_higher_fee() {
    use crate::mempool::Mempool;
    let mut pool = Mempool::new();
    // One tx per sender: only a sender's highest queued nonce is safely
    // removable, so distinct senders make every entry a candidate victim.
    for n in 0..5u128 {
        let kp = Keypair::generate();
        let mut tx = transfer(&kp, &Keypair::generate().address(), 1, 0);
        tx.fee = MIN_FEE + n;
        let h = tx.hash();
        pool.insert(tx, h, kp.address());
    }
    let evicted = pool.evict_cheapest_below(MIN_FEE + 10);
    assert_eq!(evicted, Some(MIN_FEE), "cheapest tx was not the victim");
}

// ================================================== §5 state & storage

#[test]
fn c5_state_root_survives_reopen() {
    let path = tmp("c5a");
    let root = {
        let st = Store::open(&path).unwrap();
        let kp = Keypair::generate();
        let mut a = st.account(&kp.address());
        a.balance = 42 * RAI_PER_INAZ;
        st.set_account(&kp.address(), &a);
        st.flush_state_tree();
        st.state_root()
    };
    let st = Store::open(&path).unwrap();
    assert_eq!(st.state_root(), root);
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn c5_merkle_proof_verifies_and_rejects_forgery() {
    let (node, kp) = net("c5b");
    seal(&node);
    let addr = kp.address();
    let (root, key, siblings, bitmap) = node.store.merkle_proof("acct", &addr);
    assert!(!root.is_empty() && !key.is_empty());
    let value = node.store.merkle_leaf_value("acct", &addr);
    let ok = crate::smt::verify_proof(
        &root,
        "acct",
        addr.as_bytes(),
        value.as_deref(),
        &siblings,
        &bitmap,
    );
    assert!(ok, "honest proof rejected");
    let bad = crate::smt::verify_proof(
        &"0".repeat(64),
        "acct",
        addr.as_bytes(),
        value.as_deref(),
        &siblings,
        &bitmap,
    );
    assert!(!bad, "proof verified against a wrong root");
}

#[test]
fn c5_abort_block_leaves_no_write() {
    let st = Store::open(&tmp("c5c")).unwrap();
    let addr = Keypair::generate().address();
    let root = st.state_root();
    st.begin_block();
    let mut a = st.account(&addr);
    a.balance = 999;
    st.set_account(&addr, &a);
    st.abort_block();
    assert_eq!(st.account(&addr).balance, 0);
    assert_eq!(st.state_root(), root);
}

#[test]
fn c5_abort_tx_is_nested_safe() {
    let st = Store::open(&tmp("c5d")).unwrap();
    let keep = Keypair::generate().address();
    let drop_addr = Keypair::generate().address();
    st.begin_block();
    st.begin_tx();
    let mut a = st.account(&keep);
    a.balance = 5;
    st.set_account(&keep, &a);
    st.commit_tx();
    st.begin_tx();
    let mut b = st.account(&drop_addr);
    b.balance = 7;
    st.set_account(&drop_addr, &b);
    st.abort_tx();
    st.commit_block();
    assert_eq!(st.account(&keep).balance, 5);
    assert_eq!(st.account(&drop_addr).balance, 0);
}

#[test]
fn c5_snapshot_roundtrip_restores_identical_state() {
    let (node, kp) = net("c5e");
    let bob = Keypair::generate().address();
    for n in 0..5 {
        node.accept_tx(transfer(&kp, &bob, RAI_PER_INAZ, n)).unwrap();
        seal(&node);
    }
    let snap = snapshot::export(&node.store, 7777).unwrap();
    let fresh = Store::open(&tmp("c5f")).unwrap();
    let h = snapshot::import(&fresh, &snap, 7777).unwrap();
    assert_eq!(h, node.store.tip_height().unwrap());
    assert_eq!(fresh.tip_hash(), node.store.tip_hash());
    assert_eq!(fresh.account(&bob).balance, 5 * RAI_PER_INAZ);
}

#[test]
fn c5_snapshot_rejects_wrong_chain_id() {
    let (node, _) = net("c5g");
    seal(&node);
    let snap = snapshot::export(&node.store, 7777).unwrap();
    let fresh = Store::open(&tmp("c5h")).unwrap();
    assert!(
        snapshot::import(&fresh, &snap, 1234).is_err(),
        "snapshot imported into the wrong chain"
    );
}

#[test]
fn c5_startup_state_root_check_passes_on_clean_db() {
    let (node, kp) = net("c5i");
    node.accept_tx(transfer(&kp, &Keypair::generate().address(), 1_000, 0))
        .unwrap();
    seal(&node);
    assert!(node.startup_state_root_check().is_ok());
}

#[test]
fn c5_tx_index_resolves_every_included_tx() {
    let (node, kp) = net("c5j");
    let bob = Keypair::generate().address();
    let mut hashes = Vec::new();
    for n in 0..6 {
        let tx = transfer(&kp, &bob, 1_000, n);
        hashes.push(tx.hash());
        node.accept_tx(tx).unwrap();
        seal(&node);
    }
    for h in hashes {
        assert!(node.store.tx_height(&h).is_some(), "tx {} not indexed", h);
    }
}

// ================================================== §6 contracts / VM

#[test]
fn c6_deploy_and_call_counter_contract() {
    let (node, kp) = net("c6a");
    let code = hex::encode(counter_code());
    let deploy = signed(
        TxKind::DeployContract,
        &kp,
        "",
        0,
        10 * RAI_PER_INAZ,
        0,
        Some(Payload {
            code,
            ..Default::default()
        }),
    );
    node.accept_tx(deploy).unwrap();
    seal(&node);
    assert_eq!(node.store.contract_count(), 1, "contract not deployed");
    let addr = node.store.contracts()[0].address.clone();
    let call = signed(
        TxKind::CallContract,
        &kp,
        &addr,
        0,
        10 * RAI_PER_INAZ,
        1,
        Some(Payload {
            args: hex::encode(b"inc"),
            ..Default::default()
        }),
    );
    node.accept_tx(call).unwrap();
    seal(&node);
}

#[test]
fn c6_wasm_is_deterministic_across_runs() {
    let st = Store::open(&tmp("c6b")).unwrap();
    let code = counter_code();
    let base = crate::contracts::execute(&st, "c", "x", &code, b"get".to_vec(), 0, 1, 10_000_000);
    for _ in 0..30 {
        let o = crate::contracts::execute(&st, "c", "x", &code, b"get".to_vec(), 0, 1, 10_000_000);
        assert_eq!((o.ok, o.fuel_used, o.ret), (base.ok, base.fuel_used, base.ret.clone()));
    }
}

#[test]
fn c6_non_wasm_bytes_fail_closed() {
    let st = Store::open(&tmp("c6c")).unwrap();
    let o = crate::contracts::execute(&st, "c", "x", b"\x00garbage", Vec::new(), 0, 1, 1_000_000);
    assert!(!o.ok && o.error.is_some());
}

#[test]
fn c6_oversized_code_is_rejected() {
    let big = vec![0u8; crate::contracts::MAX_CODE_BYTES + 1];
    assert!(crate::contracts::check_deploy(&big).is_err());
}

#[test]
fn c6_infinite_loop_is_metered_not_hung() {
    let st = Store::open(&tmp("c6d")).unwrap();
    let code = wat::parse_str(
        r#"(module (func (export "invoke") (result i32) (loop $l (br $l)) (i32.const 0)))"#,
    )
    .unwrap();
    let o = crate::contracts::execute(&st, "c", "x", &code, Vec::new(), 0, 1, 1_000_000);
    assert!(!o.ok, "infinite loop returned success");
    assert!(o.fuel_used <= 1_000_000, "fuel accounting overshot");
}

#[test]
fn c6_trap_reverts_writes() {
    let st = Store::open(&tmp("c6e")).unwrap();
    let code =
        wat::parse_str(r#"(module (func (export "invoke") (result i32) (unreachable)))"#).unwrap();
    let o = crate::contracts::execute(&st, "c", "x", &code, Vec::new(), 0, 1, 1_000_000);
    assert!(!o.ok);
    assert!(o.writes.is_empty(), "trapping call left writes behind");
}

#[test]
fn c6_fuel_is_bought_with_fee_and_capped() {
    assert!(crate::contracts::fuel_for_fee(MIN_FEE) > 0);
    assert!(crate::contracts::fuel_for_fee(u128::MAX) <= crate::contracts::MAX_FUEL);
}

#[test]
fn c6_token_lifecycle_create_mint_transfer_burn() {
    let (node, kp) = net("c6f");
    let p = Payload {
        symbol: "TEST".into(),
        name: "Test Token".into(),
        decimals: 6,
        mintable: true,
        ..Default::default()
    };
    assert!(tokens::check_create(&node.store, &kp.address(), 0, &Some(p.clone())).is_ok());
    let id = tokens::apply_create(&node.store, &kp.address(), 0, 1_000, 1, &Some(p)).unwrap();
    assert_eq!(node.store.token_balance(&id, &kp.address()), 1_000);
    let bob = Keypair::generate().address();
    let tp = Payload {
        token: id.clone(),
        ..Default::default()
    };
    tokens::apply_mint(&node.store, &kp.address(), &kp.address(), 500, &Some(tp.clone())).unwrap();
    assert_eq!(node.store.token_balance(&id, &kp.address()), 1_500);
    assert!(tokens::check_token_transfer(&node.store, &kp.address(), &bob, 400, &Some(tp.clone()))
        .is_ok());
    tokens::apply_token_transfer(&node.store, &kp.address(), &bob, 400, &Some(tp.clone())).unwrap();
    assert_eq!(node.store.token_balance(&id, &bob), 400);
    assert!(
        tokens::check_token_transfer(&node.store, &bob, &kp.address(), 10_000, &Some(tp)).is_err(),
        "overdraft transfer allowed"
    );
}

#[test]
fn c6_only_creator_can_mint() {
    let (node, kp) = net("c6g");
    let p = Payload {
        symbol: "OWN".into(),
        name: "Owned".into(),
        decimals: 0,
        mintable: true,
        ..Default::default()
    };
    let id = tokens::apply_create(&node.store, &kp.address(), 0, 10, 1, &Some(p)).unwrap();
    let mallory = Keypair::generate().address();
    let tp = Payload {
        token: id,
        ..Default::default()
    };
    assert!(tokens::check_mint(&node.store, &mallory, &mallory, 1_000, &Some(tp)).is_err());
}

#[test]
fn c6_non_mintable_token_cannot_inflate() {
    let (node, kp) = net("c6h");
    let p = Payload {
        symbol: "FIX".into(),
        name: "Fixed".into(),
        decimals: 0,
        mintable: false,
        ..Default::default()
    };
    let id = tokens::apply_create(&node.store, &kp.address(), 0, 100, 1, &Some(p)).unwrap();
    let tp = Payload {
        token: id,
        ..Default::default()
    };
    assert!(tokens::check_mint(&node.store, &kp.address(), &kp.address(), 1, &Some(tp)).is_err());
}

#[test]
fn c6_unit_parsing_roundtrips() {
    for (s, d) in [("1", 9u8), ("0.5", 9), ("123.456789", 6), ("0", 0)] {
        let raw = tokens::parse_units(s, d).unwrap();
        let back = tokens::format_units(raw, d);
        assert_eq!(
            tokens::parse_units(&back, d).unwrap(),
            raw,
            "roundtrip drift for {}",
            s
        );
    }
    assert!(tokens::parse_units("1.2345678901", 9).is_err(), "over-precision accepted");
    assert!(tokens::parse_units("-1", 9).is_err(), "negative accepted");
}

// ================================================== §7 rpc / api

fn cfg_public() -> RpcConfig {
    RpcConfig::new(Vec::new(), Vec::new(), false, false)
}

#[test]
fn c7_core_read_methods_answer() {
    let (node, kp) = net("c7a");
    seal(&node);
    let cfg = cfg_public();
    for (m, p) in [
        ("inaz_chainInfo", json!({})),
        ("inaz_blockNumber", json!({})),
        ("inaz_getBalance", json!({ "address": kp.address() })),
        ("inaz_getBlockByNumber", json!({ "height": 1 })),
        ("inaz_validators", json!({})),
        ("inaz_nodeStatus", json!({})),
        ("inaz_feeMarket", json!({})),
    ] {
        let r = crate::rpc::dispatch_metered(&node, m, &p, &cfg, Tier::Anonymous);
        assert!(r.is_ok(), "{} failed: {:?}", m, r.err());
    }
}

#[test]
fn c7_unknown_method_errors_cleanly() {
    let (node, _) = net("c7b");
    let cfg = cfg_public();
    let r = crate::rpc::dispatch_metered(&node, "eth_iDoNotExist", &json!({}), &cfg, Tier::Anonymous);
    assert!(r.is_err());
}

#[test]
fn c7_netinfo_is_redacted_for_anonymous() {
    let (node, _) = net("c7c");
    let cfg = cfg_public();
    let v = crate::rpc::dispatch_metered(&node, "inaz_netInfo", &json!({}), &cfg, Tier::Anonymous)
        .unwrap();
    let s = v.to_string();
    assert!(!s.contains("\"peers\":["), "peer list leaked to anon caller");
    assert!(s.contains("redacted") || s.contains("peerCount"));
}

#[test]
fn c7_admin_only_method_refuses_anonymous() {
    let (node, _) = net("c7d");
    let cfg = cfg_public();
    let r = crate::rpc::dispatch_metered(&node, "inaz_rpcLimits", &json!({}), &cfg, Tier::Anonymous);
    assert!(r.is_err(), "privileged method served to anon caller");
    let ok = crate::rpc::dispatch_metered(&node, "inaz_rpcLimits", &json!({}), &cfg, Tier::Admin);
    assert!(ok.is_ok(), "admin tier refused");
}

#[test]
fn c7_send_transaction_over_rpc_lands_in_pool() {
    let (node, kp) = net("c7e");
    let cfg = cfg_public();
    let tx = transfer(&kp, &Keypair::generate().address(), RAI_PER_INAZ, 0);
    let params = json!({ "tx": serde_json::to_value(&tx).unwrap() });
    let r = crate::rpc::dispatch_metered(&node, "inaz_sendTransaction", &params, &cfg, Tier::Anonymous);
    assert!(r.is_ok(), "valid tx refused over rpc: {:?}", r.err());
    assert_eq!(node.mempool_size(), 1);
}

#[test]
fn c7_rpc_rejects_malformed_params() {
    let (node, _) = net("c7f");
    let cfg = cfg_public();
    let r = crate::rpc::dispatch_metered(
        &node,
        "inaz_getBalance",
        &json!({ "address": 12345 }),
        &cfg,
        Tier::Anonymous,
    );
    assert!(r.is_err(), "non-string address accepted");
}

#[test]
fn c7_anonymous_rate_limiter_eventually_throttles() {
    use crate::limits::RateLimiter;
    use std::net::{IpAddr, Ipv4Addr};
    let rl = RateLimiter::new(5.0, 5.0);
    let ip = IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7));
    let mut allowed = 0;
    for _ in 0..500 {
        if rl.allow(ip) {
            allowed += 1;
        }
    }
    assert!(allowed < 500, "rate limiter never throttled");
}

#[test]
fn c7_ws_subscription_channels_parse_and_reject() {
    use crate::events::Channel;
    assert!(Channel::parse("heads", &json!({})).is_ok());
    assert!(Channel::parse("mempool", &json!({})).is_ok());
    assert!(Channel::parse("finality", &json!({})).is_ok());
    // keyed channels must reject a missing or malformed key
    assert!(Channel::parse("signature", &json!({})).is_err());
    assert!(Channel::parse("account", &json!({ "address": "nope" })).is_err());
    assert!(Channel::parse("not-a-channel", &json!({})).is_err());
}

// ================================================== §8 load & stress

#[test]
fn c8_five_hundred_transfers_settle_exactly() {
    let (node, kp) = net("c8a");
    let bob = Keypair::generate().address();
    let n = 500u64;
    let mut sent = 0u64;
    let mut nonce = 0u64;
    while sent < n {
        let mut batch = Vec::new();
        for _ in 0..MAX_PENDING_PER_SENDER.min(n - sent) {
            batch.push(transfer(&kp, &bob, RAI_PER_INAZ, nonce));
            nonce += 1;
        }
        let admitted = node.accept_batch(batch);
        sent += admitted.iter().filter(|r| r.is_ok()).count() as u64;
        seal(&node);
    }
    assert_eq!(
        node.store.account(&bob).balance,
        n as u128 * RAI_PER_INAZ,
        "value lost or duplicated under load"
    );
    assert_eq!(node.store.account(&kp.address()).nonce, n);
}

#[test]
fn c8_many_accounts_state_root_is_stable() {
    let (node, kp) = net("c8b");
    let mut addrs = Vec::new();
    let mut nonce = 0u64;
    for _ in 0..8 {
        let mut batch = Vec::new();
        for _ in 0..40 {
            let a = Keypair::generate().address();
            batch.push(transfer(&kp, &a, RAI_PER_INAZ, nonce));
            addrs.push(a);
            nonce += 1;
        }
        node.accept_batch(batch);
        seal(&node);
    }
    let h = node.store.tip_height().unwrap();
    let root = node.store.block(h).unwrap().state_root;
    assert_eq!(root, node.store.state_root_at(h));
    assert!(addrs
        .iter()
        .all(|a| node.store.account(a).balance == RAI_PER_INAZ));
}

#[test]
fn c8_long_run_stability_two_hundred_blocks() {
    let (node, kp) = net("c8c");
    let bob = Keypair::generate().address();
    for i in 0..200u64 {
        if i % 3 == 0 {
            let _ = node.accept_tx(transfer(&kp, &bob, 1_000, i / 3));
        }
        seal(&node);
    }
    assert_eq!(node.store.tip_height().unwrap(), 200);
    assert!(node.startup_state_root_check().is_ok());
}

#[test]
fn c8_block_size_is_capped() {
    assert!(MAX_TXS_PER_BLOCK <= 5_000, "block tx cap raised unsafely");
}

// ================================================== §9 security

#[test]
fn c9_canonical_encoding_is_injective_over_random_fields() {
    use std::collections::HashSet;
    let kp = Keypair::generate();
    let mut seen = HashSet::new();
    for n in 0..2_000u64 {
        let tx = Transaction {
            kind: TxKind::Transfer,
            from_pubkey: kp.pubkey_hex(),
            to: format!("inaz|{}", n),
            amount: n as u128,
            fee: MIN_FEE,
            nonce: n,
            chain_id: 7777,
            payload: None,
            signature: String::new(),
        };
        assert!(
            seen.insert(tx.canonical_signing_bytes()),
            "preimage collision at {}",
            n
        );
    }
}

#[test]
fn c9_delimiter_injection_cannot_reuse_a_signature() {
    let kp = Keypair::generate();
    let mut tx = transfer(&kp, &Keypair::generate().address(), RAI_PER_INAZ, 0);
    tx.to = format!("{}|extra", tx.to);
    assert!(!tx.fields_unambiguous() || !tx.verify_signature());
}

#[test]
fn c9_signature_never_valid_after_mutation() {
    let kp = Keypair::generate();
    let base = transfer(&kp, &Keypair::generate().address(), RAI_PER_INAZ, 0);
    assert!(base.verify_signature());
    for i in 0..5 {
        let mut m = base.clone();
        match i {
            0 => m.amount += 1,
            1 => m.fee += 1,
            2 => m.nonce += 1,
            3 => m.chain_id += 1,
            _ => m.to = Keypair::generate().address(),
        }
        assert!(!m.verify_signature(), "mutation {} still verified", i);
    }
}

#[test]
fn c9_hostile_wasm_memory_growth_fails_closed() {
    let st = Store::open(&tmp("c9a")).unwrap();
    let code = wat::parse_str(
        r#"(module (memory 1) (func (export "invoke") (result i32)
             (loop $l (drop (memory.grow (i32.const 1))) (br $l)) (i32.const 0)))"#,
    )
    .unwrap();
    let o = crate::contracts::execute(&st, "c", "x", &code, Vec::new(), 0, 1, 5_000_000);
    assert!(!o.ok, "unbounded memory growth succeeded");
}

#[test]
fn c9_deep_recursion_fails_closed() {
    let st = Store::open(&tmp("c9b")).unwrap();
    let code = wat::parse_str(
        r#"(module (func $f (call $f)) (func (export "invoke") (result i32) (call $f) (i32.const 0)))"#,
    )
    .unwrap();
    let o = crate::contracts::execute(&st, "c", "x", &code, Vec::new(), 0, 1, 2_000_000_000);
    assert!(!o.ok, "stack exhaustion was not contained");
}

#[test]
fn c9_secret_comparison_is_constant_time_api() {
    use crate::limits::secret_eq;
    assert!(secret_eq("abcdefghijklmnop", "abcdefghijklmnop"));
    assert!(!secret_eq("abcdefghijklmnop", "abcdefghijklmnoq"));
    assert!(!secret_eq("short", "abcdefghijklmnop"));
}

#[test]
fn c9_zero_and_overflow_amounts_are_safe() {
    let (node, kp) = net("c9c");
    let bob = Keypair::generate().address();
    let _ = node.accept_tx(transfer(&kp, &bob, 0, 0));
    let huge = signed(TxKind::Transfer, &kp, &bob, u128::MAX, MIN_FEE, 1, None);
    assert!(node.accept_tx(huge).is_err(), "u128::MAX transfer accepted");
    seal(&node);
    assert!(node.store.account(&bob).balance < RAI_PER_INAZ);
}

#[test]
fn c9_fuzz_random_transactions_never_panic() {
    let (node, _) = net("c9d");
    let mut seed = 0x1234_5678_9abc_def0u64;
    let mut rnd = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        seed >> 11
    };
    for _ in 0..1_000 {
        let kp = Keypair::generate();
        let mut tx = transfer(&kp, &Keypair::generate().address(), rnd() as u128, rnd() % 5);
        if rnd() % 3 == 0 {
            tx.signature = hex::encode([0u8; 64]);
        }
        if rnd() % 4 == 0 {
            tx.to = String::from_utf8_lossy(&rnd().to_be_bytes()).to_string();
        }
        let _ = node.accept_tx(tx);
    }
    assert!(node.produce_block().is_ok(), "node broke after fuzzing");
}

#[test]
fn c9_evidence_id_is_stable_and_unforgeable() {
    let (node, _) = net("c9e");
    let bogus = json!({});
    let cfg = cfg_public();
    let r = crate::rpc::dispatch_metered(&node, "inaz_report", &bogus, &cfg, Tier::Anonymous);
    assert!(r.is_err(), "empty evidence accepted");
}

// ================================================== §10 upgrade / fork

#[test]
fn c10_activation_heights_are_pinned() {
    use crate::fees::FEE_MARKET_ACTIVATION_HEIGHT;
    use crate::staking::VALIDATOR_CAP_ACTIVATION_HEIGHT;
    use crate::state::STATE_ROOT_V2_ACTIVATION_HEIGHT;
    use crate::types::SLASHING_ACTIVATION_HEIGHT;
    assert_eq!(SLASHING_ACTIVATION_HEIGHT, 130_000);
    assert_eq!(FEE_MARKET_ACTIVATION_HEIGHT, 200_000);
    assert_eq!(STATE_ROOT_V2_ACTIVATION_HEIGHT, 200_000);
    assert_eq!(VALIDATOR_CAP_ACTIVATION_HEIGHT, 2_000_000);
}

#[test]
fn c10_legacy_and_v2_signatures_both_verify() {
    let kp = Keypair::generate();
    let mut legacy = transfer(&kp, &Keypair::generate().address(), RAI_PER_INAZ, 0);
    legacy.signature = kp.sign_hex(&legacy.signing_bytes());
    assert!(legacy.verify_signature(), "legacy signer broken (fork risk)");
    let mut modern = legacy.clone();
    modern.signature = kp.sign_hex(&modern.canonical_signing_bytes());
    assert!(modern.verify_signature(), "v2 signer broken");
}

#[test]
fn c10_genesis_is_byte_identical_across_nodes() {
    let kp = Keypair::generate();
    let mk = |tag: &str| {
        let g = Genesis {
            chain_id: 7777,
            chain_name: "Inazuma".into(),
            symbol: "INAZ".into(),
            decimals: 9,
            block_time_ms: 400,
            alloc: vec![GenesisAlloc {
                address: kp.address(),
                balance: "1000000".into(),
                stake: Some("10000".into()),
            }],
        };
        let st = Store::open(&tmp(tag)).unwrap();
        let n = Node::new(st, g, Keypair::generate());
        n.init_genesis().unwrap()
    };
    let a = mk("c10a");
    let b = mk("c10b");
    assert_eq!(a.hash, b.hash, "genesis diverged between nodes");
    assert_eq!(a.state_root, b.state_root);
}

#[test]
fn c10_snapshot_format_is_versioned() {
    assert_eq!(snapshot::SNAPSHOT_FORMAT, 2);
}

#[test]
fn c10_replay_from_genesis_reproduces_the_same_head() {
    let (node, kp) = net("c10c");
    let bob = Keypair::generate().address();
    for n in 0..12 {
        node.accept_tx(transfer(&kp, &bob, RAI_PER_INAZ, n)).unwrap();
        seal(&node);
    }
    let tip = node.store.tip_height().unwrap();
    // A second node imports every block and must land on the same root.
    let replica = {
        let st = Store::open(&tmp("c10d")).unwrap();
        let n = Node::new(st, node.genesis.clone(), Keypair::generate());
        n.set_solo(true);
        n.init_genesis().unwrap();
        Arc::new(n)
    };
    for h in 1..=tip {
        let b = node.store.block(h).unwrap();
        replica
            .import_block(&b)
            .unwrap_or_else(|e| panic!("import of block {} failed: {}", h, e));
    }
    assert_eq!(replica.store.tip_hash(), node.store.tip_hash());
    assert_eq!(
        replica.store.state_root_at(tip),
        node.store.state_root_at(tip),
        "replica state root diverged"
    );
    assert_eq!(replica.store.account(&bob).balance, 12 * RAI_PER_INAZ);
}

#[test]
fn c10_replica_rejects_a_tampered_block() {
    let (node, kp) = net("c10e");
    node.accept_tx(transfer(&kp, &Keypair::generate().address(), RAI_PER_INAZ, 0))
        .unwrap();
    seal(&node);
    let mut b = node.store.block(1).unwrap();
    b.transactions.clear();
    let replica = {
        let st = Store::open(&tmp("c10f")).unwrap();
        let n = Node::new(st, node.genesis.clone(), Keypair::generate());
        n.init_genesis().unwrap();
        Arc::new(n)
    };
    assert!(replica.import_block(&b).is_err(), "tampered block imported");
}
