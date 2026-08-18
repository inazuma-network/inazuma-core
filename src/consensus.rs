//! Inazuma finality: stake-weighted precommit votes with a 2/3 threshold.
//!
//! Block production is optimistic (the elected leader seals a block every slot).
//! Finality is separate: every validator signs a precommit over `(height, hash)`
//! and gossips it. Once precommits representing more than two thirds of the
//! staked INAZ agree on the same hash, that height is final and can never be
//! reorged by this node.

use crate::crypto::{address_from_pubkey, verify};
use crate::slashing::Evidence;
use crate::staking;
use crate::state::Store;
use crate::types::CHAIN_ID;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub height: u64,
    pub hash: String,
    /// Voting validator's public key, hex. The validator address derives from it.
    pub voter_pubkey: String,
    #[serde(default)]
    pub signature: String,
}

impl Vote {
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!("inazuma-vote|{}|{}|{}", CHAIN_ID, self.height, self.hash).into_bytes()
    }

    pub fn voter(&self) -> Option<String> {
        let raw = hex::decode(&self.voter_pubkey).ok()?;
        if raw.len() != 32 {
            return None;
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&raw);
        Some(address_from_pubkey(&pk))
    }

    pub fn verify_signature(&self) -> bool {
        // Same rule as transactions: a `|` inside a signed field could move the
        // field boundaries and let one signature cover two different votes.
        // Block hashes and pubkeys are hex, so this only ever rejects forgeries.
        crate::types::delimiter_free(&self.hash)
            && crate::types::delimiter_free(&self.voter_pubkey)
            && verify(&self.voter_pubkey, &self.signing_bytes(), &self.signature)
    }
}

/// Precommits this node has seen, keyed by height then voter address.
#[derive(Default)]
pub struct VoteTracker {
    inner: Mutex<HashMap<u64, HashMap<String, Vote>>>,
    /// Votes that arrived before the block they refer to. Replayed on import.
    pending: Mutex<Vec<Vote>>,
    /// Equivocation proofs collected from conflicting votes, waiting to be
    /// gossiped and reported on chain.
    evidence: Mutex<Vec<Evidence>>,
}

#[derive(Debug)]
pub struct VoteOutcome {
    /// True when this vote was new and worth gossiping onward.
    pub fresh: bool,
    /// Set when this vote pushed the height over the 2/3 stake threshold.
    pub finalized: Option<u64>,
}

impl VoteTracker {
    pub fn new() -> Self {
        VoteTracker::default()
    }

    /// Record a precommit. Only votes from bonded validators on a block this node
    /// already stores are counted, so a peer cannot vote a block into existence.
    pub fn add(&self, store: &Store, vote: Vote) -> Result<VoteOutcome, String> {
        if !vote.verify_signature() {
            return Err("invalid vote signature".into());
        }
        let voter = vote.voter().ok_or("invalid voter public key")?;
        // Two different precommits at the same height from the same validator is
        // provable equivocation: keep the pair as evidence.
        if let Some(prev) = self.first_vote(vote.height, &voter) {
            if prev.hash != vote.hash {
                self.push_evidence(Evidence::Vote {
                    a: prev,
                    b: vote.clone(),
                });
                return Err("equivocating vote: evidence recorded".into());
            }
        }
        if vote.height <= store.finalized_height() {
            return Ok(VoteOutcome {
                fresh: false,
                finalized: None,
            });
        }
        match store.block(vote.height) {
            Some(b) if b.hash == vote.hash => {}
            Some(_) => return Err("vote for a different block at this height".into()),
            None => {
                // The block is still in flight; keep the vote and replay it later.
                //
                // Only bonded validators may occupy this buffer. It used to
                // accept any signed vote, so anyone could generate 4,096 throwaway
                // keys, fill the buffer with votes for heights that will never
                // exist, and push out the real precommits as they arrived —
                // stalling finality for free, with no stake at risk.
                let set = staking::validator_set(store);
                if !set.iter().any(|v| v.address == voter) {
                    return Err("voter is not a bonded validator".into());
                }
                let mut pending = self.pending.lock().unwrap();
                // One slot per (validator, height) so a single validator cannot
                // crowd the buffer either.
                if pending
                    .iter()
                    .any(|v| v.height == vote.height && v.voter_pubkey == vote.voter_pubkey)
                {
                    return Ok(VoteOutcome {
                        fresh: false,
                        finalized: None,
                    });
                }
                // Bound the buffer by the set size, not by an arbitrary constant.
                let cap = (set.len().max(1) * 64).min(4_096);
                if pending.len() >= cap {
                    pending.remove(0);
                }
                pending.push(vote);
                return Ok(VoteOutcome {
                    fresh: true,
                    finalized: None,
                });
            }
        }
        let set = staking::validator_set(store);
        let total = staking::total_stake(&set);
        if !set.iter().any(|v| v.address == voter) {
            return Err("voter is not a bonded validator".into());
        }

        let mut guard = self.inner.lock().unwrap();
        let at_height = guard.entry(vote.height).or_default();
        let fresh = !at_height.contains_key(&voter);
        at_height.insert(voter, vote.clone());

        let voted: u128 = set
            .iter()
            .filter(|v| at_height.contains_key(&v.address))
            .map(|v| v.stake)
            .sum();
        let mut finalized = None;
        if total > 0 && voted * 3 > total * 2 && vote.height > store.finalized_height() {
            store.set_finalized_height(vote.height);
            finalized = Some(vote.height);
            guard.retain(|h, _| *h > vote.height);
        }
        Ok(VoteOutcome { fresh, finalized })
    }

    /// How much stake has precommitted a height, and how much exists in total.
    pub fn tally(&self, store: &Store, height: u64) -> (u128, u128) {
        let set = staking::validator_set(store);
        let total = staking::total_stake(&set);
        let guard = self.inner.lock().unwrap();
        let voted = match guard.get(&height) {
            Some(at) => set
                .iter()
                .filter(|v| at.contains_key(&v.address))
                .map(|v| v.stake)
                .sum(),
            None => 0,
        };
        (voted, total)
    }

    pub fn seen(&self, height: u64) -> usize {
        self.inner
            .lock()
            .unwrap()
            .get(&height)
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// The first precommit this node saw from `voter` at `height`, if any.
    fn first_vote(&self, height: u64, voter: &str) -> Option<Vote> {
        self.inner.lock().unwrap().get(&height)?.get(voter).cloned()
    }

    fn push_evidence(&self, evidence: Evidence) {
        let mut queue = self.evidence.lock().unwrap();
        if queue.iter().any(|e| e.id() == evidence.id()) {
            return;
        }
        if queue.len() > 64 {
            queue.remove(0);
        }
        queue.push(evidence);
    }

    /// Drain proofs gathered from conflicting votes.
    pub fn take_evidence(&self) -> Vec<Evidence> {
        std::mem::take(&mut *self.evidence.lock().unwrap())
    }

    /// Replay buffered votes for a height that just landed. Returns the height
    /// finalized by the replay, if any.
    pub fn replay_pending(&self, store: &Store, height: u64) -> Option<u64> {
        let ready: Vec<Vote> = {
            let mut pending = self.pending.lock().unwrap();
            let (ready, keep): (Vec<Vote>, Vec<Vote>) =
                pending.drain(..).partition(|v| v.height == height);
            *pending = keep
                .into_iter()
                .filter(|v| v.height > store.finalized_height())
                .collect();
            ready
        };
        let mut finalized = None;
        for v in ready {
            if let Ok(outcome) = self.add(store, v) {
                if let Some(h) = outcome.finalized {
                    finalized = Some(h);
                }
            }
        }
        finalized
    }
}
