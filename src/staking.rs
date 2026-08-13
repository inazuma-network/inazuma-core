//! Inazuma proof-of-stake: validator set, stake-weighted leader election, rewards.
//!
//! INAZ is the staking coin. Nobody has to hold another chain's token to validate:
//! stake `MIN_STAKE` INAZ and the address enters the validator set.

use crate::crypto::sha256;
use crate::state::Store;
use crate::types::{Account, RAI_PER_INAZ};

/// Newly issued INAZ per block, shared by the validator set.
pub const BLOCK_REWARD: u128 = RAI_PER_INAZ / 100; // 0.01 INAZ
/// Share of the block reward the elected leader keeps for doing the work.
pub const LEADER_COMMISSION_PCT: u128 = 20;

#[derive(Debug, Clone)]
pub struct Validator {
    pub address: String,
    pub stake: u128,
    pub rewards: u128,
    pub blocks_produced: u64,
    /// Height this validator becomes electable again (0 = active).
    pub jailed_until: u64,
    pub tombstoned: bool,
    pub missed_slots: u64,
    pub slashed: u128,
}

/// Active validator set at the chain tip: bonded, not jailed, in address order.
pub fn validator_set(store: &Store) -> Vec<Validator> {
    let height = store.tip_height().unwrap_or(0) + 1;
    validator_set_at(store, height)
}

/// Active validator set as of `height`: every account staking at least
/// `MIN_STAKE` that is neither jailed nor tombstoned, in address order.
pub fn validator_set_at(store: &Store, height: u64) -> Vec<Validator> {
    store
        .stake_accounts()
        .into_iter()
        .filter(|(_, a)| a.is_active_validator(height))
        .map(|(address, a)| Validator {
            address,
            stake: a.staked,
            rewards: a.rewards,
            blocks_produced: a.blocks_produced,
            jailed_until: a.penalties.jailed_until,
            tombstoned: a.penalties.tombstoned,
            missed_slots: a.penalties.missed_slots,
            slashed: a.penalties.slashed,
        })
        .collect()
}

/// Every bonded account including jailed and tombstoned ones, for reporting.
pub fn bonded_set(store: &Store) -> Vec<Validator> {
    store
        .stake_accounts()
        .into_iter()
        .filter(|(_, a)| a.staked > 0)
        .map(|(address, a)| Validator {
            address,
            stake: a.staked,
            rewards: a.rewards,
            blocks_produced: a.blocks_produced,
            jailed_until: a.penalties.jailed_until,
            tombstoned: a.penalties.tombstoned,
            missed_slots: a.penalties.missed_slots,
            slashed: a.penalties.slashed,
        })
        .collect()
}

pub fn total_stake(set: &[Validator]) -> u128 {
    set.iter().map(|v| v.stake).sum()
}

/// Deterministic, stake-weighted leader for a height. Every node computes the same
/// answer from the parent hash, so no coordination is needed to know whose slot it is.
pub fn elect_leader(set: &[Validator], height: u64, parent_hash: &str) -> Option<String> {
    elect_leader_attempt(set, height, parent_hash, 0)
}

/// Leader for a height on a given attempt. Attempt 0 is the primary slot owner.
/// If that validator misses its slot, every node deterministically moves to
/// attempt 1, then 2, and so on, so a single offline validator cannot stall the
/// chain and no two nodes disagree about whose turn it is.
pub fn elect_leader_attempt(
    set: &[Validator],
    height: u64,
    parent_hash: &str,
    attempt: u64,
) -> Option<String> {
    let total = total_stake(set);
    if set.is_empty() || total == 0 {
        return None;
    }
    let seed = sha256(format!("inazuma-leader|{}|{}|{}", height, parent_hash, attempt).as_bytes());
    let mut draw_bytes = [0u8; 16];
    draw_bytes.copy_from_slice(&seed[..16]);
    let draw = u128::from_be_bytes(draw_bytes) % total;
    let mut cursor: u128 = 0;
    for v in set {
        cursor += v.stake;
        if draw < cursor {
            return Some(v.address.clone());
        }
    }
    set.last().map(|v| v.address.clone())
}

/// Credit a sealed block's fees and reward. The leader takes the fees plus a
/// commission; the rest of the reward is split across the set by stake.
pub fn pay_rewards(store: &Store, leader: &str, fees: u128) {
    let set = validator_set(store);
    let total = total_stake(&set);

    if set.is_empty() || total == 0 {
        // Bootstrap: no stake on chain yet, the running node keeps everything.
        let mut acct = store.account(leader);
        acct.balance += fees + BLOCK_REWARD;
        acct.rewards += BLOCK_REWARD;
        acct.blocks_produced += 1;
        store.set_account(leader, &acct);
        return;
    }

    let commission = BLOCK_REWARD * LEADER_COMMISSION_PCT / 100;
    let shared = BLOCK_REWARD - commission;
    let mut distributed: u128 = 0;

    for v in &set {
        let cut = shared * v.stake / total;
        if cut == 0 {
            continue;
        }
        distributed += cut;
        credit(store, &v.address, cut);
    }

    // Leader gets fees, commission, and any rounding dust.
    let leader_total = fees + commission + (shared - distributed);
    let mut acct: Account = store.account(leader);
    acct.balance += leader_total;
    acct.rewards += commission + (shared - distributed);
    acct.blocks_produced += 1;
    store.set_account(leader, &acct);
}

fn credit(store: &Store, address: &str, amount: u128) {
    let mut acct = store.account(address);
    acct.balance += amount;
    acct.rewards += amount;
    store.set_account(address, &acct);
}

/// Release every unbonding entry that has matured at `height`.
/// Returns the addresses that were unlocked.
pub fn release_unbonded(store: &Store, height: u64) -> Vec<String> {
    let mut unlocked = Vec::new();
    for (address, mut acct) in store.stake_accounts() {
        if acct.unbonding.is_empty() {
            continue;
        }
        let before = acct.unbonding.len();
        let mut released: u128 = 0;
        acct.unbonding.retain(|u| {
            if u.release_height <= height {
                released += u.amount;
                false
            } else {
                true
            }
        });
        if acct.unbonding.len() != before {
            acct.balance += released;
            store.set_account(&address, &acct);
            unlocked.push(address);
        }
    }
    unlocked
}
