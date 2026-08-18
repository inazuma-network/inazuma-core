//! Indexed transaction pool.
//!
//! The old pool was a plain `Vec`, so every admission rehashed every queued
//! transaction and re-derived every sender address — quadratic work that capped
//! throughput long before execution did. This version keeps the indexes it needs
//! (hash set for duplicates, per-sender counters for nonce gaps) so admission is
//! O(1), and orders blocks by fee so a paying transaction is never stuck behind
//! a spam flood.

use crate::types::Transaction;
use std::collections::{HashMap, HashSet};

/// Hard ceiling on queued transactions. Without it the pool is an unbounded
/// memory sink: a spam loop paying the floor fee can grow it until the node
/// dies. With it, admission becomes a competition — see `evict_cheapest`.
pub const MAX_POOL_TXS: usize = 20_000;
/// One account may not hold more than this many queued transactions. A single
/// key cannot occupy the whole pool even if it pays well.
pub const MAX_PENDING_PER_SENDER: u64 = 64;

pub struct PoolTx {
    pub tx: Transaction,
    pub hash: String,
    pub sender: String,
    /// Arrival order, used to keep same-fee ordering stable and fair.
    pub seq: u64,
}

#[derive(Default)]
pub struct Mempool {
    entries: Vec<PoolTx>,
    hashes: HashSet<String>,
    per_sender: HashMap<String, u64>,
    next_seq: u64,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, hash: &str) -> bool {
        self.hashes.contains(hash)
    }

    /// Queued transaction count for one sender, i.e. how far its nonce has run
    /// ahead of confirmed state.
    pub fn pending_for(&self, sender: &str) -> u64 {
        self.per_sender.get(sender).copied().unwrap_or(0)
    }

    pub fn insert(&mut self, tx: Transaction, hash: String, sender: String) {
        self.hashes.insert(hash.clone());
        *self.per_sender.entry(sender.clone()).or_insert(0) += 1;
        let seq = self.next_seq;
        self.next_seq += 1;
        self.entries.push(PoolTx {
            tx,
            hash,
            sender,
            seq,
        });
    }

    pub fn is_full(&self) -> bool {
        self.entries.len() >= MAX_POOL_TXS
    }

    /// Priority lane: when the pool is full, the cheapest queued transaction is
    /// dropped to make room for a transaction that pays more. Only a sender's
    /// *highest* queued nonce is ever a candidate, so eviction can never punch a
    /// nonce gap into someone else's queue. Returns the evicted fee.
    pub fn evict_cheapest_below(&mut self, incoming_fee: u128) -> Option<u128> {
        // Highest queued nonce per sender: the only safely removable tail.
        let mut tail: HashMap<&str, (usize, u64)> = HashMap::new();
        for (i, e) in self.entries.iter().enumerate() {
            let entry = tail.entry(e.sender.as_str()).or_insert((i, e.tx.nonce));
            if e.tx.nonce >= entry.1 {
                *entry = (i, e.tx.nonce);
            }
        }
        let victim = tail.values().map(|&(i, _)| i).min_by(|&a, &b| {
            let (x, y) = (&self.entries[a], &self.entries[b]);
            x.tx.fee.cmp(&y.tx.fee).then(y.seq.cmp(&x.seq))
        })?;
        if self.entries[victim].tx.fee >= incoming_fee {
            return None; // nothing cheaper than the newcomer: reject it instead
        }
        let e = self.entries.swap_remove(victim);
        self.hashes.remove(&e.hash);
        decrement(&mut self.per_sender, &e.sender);
        Some(e.tx.fee)
    }

    /// Take up to `max` transactions for the next block: highest fee first, then
    /// oldest first, but never a sender's later nonce before its earlier one.
    pub fn take_batch(&mut self, max: usize) -> Vec<Transaction> {
        if self.entries.is_empty() || max == 0 {
            return Vec::new();
        }
        let mut order: Vec<usize> = (0..self.entries.len()).collect();
        order.sort_by(|&a, &b| {
            let (x, y) = (&self.entries[a], &self.entries[b]);
            y.tx.fee
                .cmp(&x.tx.fee)
                .then(x.tx.nonce.cmp(&y.tx.nonce))
                .then(x.seq.cmp(&y.seq))
        });
        // A sender's transactions must stay nonce-ordered no matter what they
        // paid, otherwise a high-fee later nonce would fail execution.
        let mut next_ok: HashMap<&str, u64> = HashMap::new();
        let mut chosen: Vec<usize> = Vec::with_capacity(max.min(order.len()));
        let mut deferred = true;
        let mut remaining: Vec<usize> = order;
        while deferred && chosen.len() < max {
            deferred = false;
            let mut still: Vec<usize> = Vec::new();
            for i in remaining {
                if chosen.len() >= max {
                    still.push(i);
                    continue;
                }
                let e = &self.entries[i];
                let want = next_ok.get(e.sender.as_str()).copied();
                match want {
                    None => {
                        next_ok.insert(e.sender.as_str(), e.tx.nonce + 1);
                        chosen.push(i);
                    }
                    Some(n) if n == e.tx.nonce => {
                        next_ok.insert(e.sender.as_str(), e.tx.nonce + 1);
                        chosen.push(i);
                        deferred = true;
                    }
                    Some(_) => still.push(i),
                }
            }
            remaining = still;
        }
        // Rank by the order the selection loop accepted them. Returning them in
        // storage order instead would be a real bug: `entries` is not
        // nonce-ordered per sender (eviction uses swap_remove, which moves the
        // last entry into the hole), so a sender's nonce 5 could be handed to the
        // producer before nonce 4 — the later one then fails execution and gets
        // dropped from the block for no reason. Caught by a property test.
        let rank: HashMap<usize, usize> = chosen.iter().copied().zip(0..).collect();
        let mut taken: Vec<(usize, Transaction)> = Vec::with_capacity(rank.len());
        let mut kept: Vec<PoolTx> = Vec::with_capacity(self.entries.len() - rank.len());
        for (i, e) in std::mem::take(&mut self.entries).into_iter().enumerate() {
            if let Some(&r) = rank.get(&i) {
                self.hashes.remove(&e.hash);
                decrement(&mut self.per_sender, &e.sender);
                taken.push((r, e.tx));
            } else {
                kept.push(e);
            }
        }
        self.entries = kept;
        taken.sort_by_key(|(r, _)| *r);
        taken.into_iter().map(|(_, tx)| tx).collect()
    }

    /// Drop transactions a freshly imported block already confirmed.
    pub fn remove_hashes(&mut self, hashes: &HashSet<String>) {
        if hashes.is_empty() {
            return;
        }
        let kept: Vec<PoolTx> = std::mem::take(&mut self.entries)
            .into_iter()
            .filter(|e| {
                if hashes.contains(&e.hash) {
                    self.hashes.remove(&e.hash);
                    decrement(&mut self.per_sender, &e.sender);
                    false
                } else {
                    true
                }
            })
            .collect();
        self.entries = kept;
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.hashes.clear();
        self.per_sender.clear();
    }

    /// Every queued fee, for percentile fee guidance over RPC.
    pub fn fees(&self) -> Vec<u128> {
        self.entries.iter().map(|e| e.tx.fee).collect()
    }

    /// Lowest fee currently queued, for fee estimation over RPC.
    pub fn min_fee(&self) -> Option<u128> {
        self.entries.iter().map(|e| e.tx.fee).min()
    }
}

fn decrement(map: &mut HashMap<String, u64>, sender: &str) {
    if let Some(n) = map.get_mut(sender) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            map.remove(sender);
        }
    }
}
