//! Inazuma slashing: equivocation burns, downtime jailing and evidence proofs.
//!
//! Two offences are punished, and both are proved with signatures that only the
//! offender could have produced — no committee vote, no admin key.
//!
//!   * **Equivocation** — signing two different blocks, or two different
//!     precommit votes, at the same height. Proof is the two signed objects.
//!     Punishment is a stake burn plus a permanent tombstone.
//!   * **Downtime** — being elected leader and never sealing the block.
//!     Derived from block history, so every node reaches the same verdict.
//!     Punishment is a jail (no burn on a first offence).
//!
//! Inazuma's twist on the Ethereum/Cosmos designs: the equivocation burn is
//! *correlated with stake share*. A validator holding 40% of the stake burns far
//! more than one holding 2%, because a large validator equivocating is the only
//! version of the attack that can actually threaten finality.

use crate::consensus::Vote;
use crate::crypto::{address_from_pubkey, verify};
use crate::state::Store;
use crate::types::{
    Block, Payload, DOWNTIME_JAIL_BLOCKS, DOWNTIME_JAIL_STREAK, DOWNTIME_REPEAT_BURN_BPS,
    EQUIVOCATION_CORRELATION_FACTOR, EQUIVOCATION_MIN_BURN_PCT, EVIDENCE_MAX_AGE_BLOCKS,
    REPORTER_BOUNTY_PCT, SLASHING_ACTIVATION_HEIGHT, TOMBSTONE_HEIGHT,
};
use serde::{Deserialize, Serialize};

/// A signed block header, enough to prove who sealed what without the body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderProof {
    pub height: u64,
    pub parent_hash: String,
    pub timestamp_ms: u128,
    pub state_root: String,
    pub txs_root: String,
    pub producer: String,
    pub producer_pubkey: String,
    pub signature: String,
    pub hash: String,
}

impl HeaderProof {
    pub fn from_block(b: &Block) -> Self {
        HeaderProof {
            height: b.height,
            parent_hash: b.parent_hash.clone(),
            timestamp_ms: b.timestamp_ms,
            state_root: b.state_root.clone(),
            txs_root: b.txs_root.clone(),
            producer: b.producer.clone(),
            producer_pubkey: b.producer_pubkey.clone(),
            signature: b.signature.clone(),
            hash: b.hash.clone(),
        }
    }

    fn as_block(&self) -> Block {
        Block {
            height: self.height,
            parent_hash: self.parent_hash.clone(),
            timestamp_ms: self.timestamp_ms,
            state_root: self.state_root.clone(),
            txs_root: self.txs_root.clone(),
            producer: self.producer.clone(),
            producer_pubkey: self.producer_pubkey.clone(),
            transactions: Vec::new(),
            signature: self.signature.clone(),
            hash: self.hash.clone(),
        }
    }

    /// The producer really signed this header and owns the producer address.
    pub fn is_authentic(&self) -> bool {
        self.as_block().verify_producer()
    }
}

/// Proof of an offence. Verified by anyone, from the signatures alone.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Evidence {
    /// Two conflicting blocks sealed at the same height by the same producer.
    Block { a: HeaderProof, b: HeaderProof },
    /// Two conflicting precommits cast at the same height by the same validator.
    Vote { a: Vote, b: Vote },
}

impl Evidence {
    pub fn label(&self) -> &'static str {
        match self {
            Evidence::Block { .. } => "double-sign",
            Evidence::Vote { .. } => "double-vote",
        }
    }

    pub fn height(&self) -> u64 {
        match self {
            Evidence::Block { a, .. } => a.height,
            Evidence::Vote { a, .. } => a.height,
        }
    }

    /// Deterministic id, so the same offence can only be slashed once.
    pub fn id(&self) -> String {
        let (offender, mut hashes) = match self {
            Evidence::Block { a, b } => (a.producer.clone(), vec![a.hash.clone(), b.hash.clone()]),
            Evidence::Vote { a, b } => (
                a.voter().unwrap_or_default(),
                vec![a.hash.clone(), b.hash.clone()],
            ),
        };
        hashes.sort();
        format!("{}:{}:{}:{}", self.label(), self.height(), offender, hashes.join("+"))
    }

    /// Check the proof stands on its own. Returns the offender's address.
    pub fn verify(&self) -> Result<String, String> {
        match self {
            Evidence::Block { a, b } => {
                if a.height != b.height {
                    return Err("evidence heights differ".into());
                }
                if a.height == 0 {
                    return Err("genesis cannot equivocate".into());
                }
                if a.hash == b.hash {
                    return Err("both headers are the same block".into());
                }
                if a.producer != b.producer || a.producer_pubkey != b.producer_pubkey {
                    return Err("headers were sealed by different validators".into());
                }
                if !a.is_authentic() || !b.is_authentic() {
                    return Err("header signature does not verify".into());
                }
                Ok(a.producer.clone())
            }
            Evidence::Vote { a, b } => {
                if a.height != b.height {
                    return Err("evidence heights differ".into());
                }
                if a.height == 0 {
                    return Err("no votes at genesis".into());
                }
                if a.hash == b.hash {
                    return Err("both votes cover the same block".into());
                }
                if a.voter_pubkey != b.voter_pubkey {
                    return Err("votes came from different validators".into());
                }
                if !a.verify_signature() || !b.verify_signature() {
                    return Err("vote signature does not verify".into());
                }
                let voter = a.voter().ok_or("invalid voter public key")?;
                // Belt and braces: the address must derive from the signed key.
                let raw = hex::decode(&a.voter_pubkey).map_err(|_| "bad pubkey hex")?;
                if raw.len() != 32 {
                    return Err("bad pubkey length".into());
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&raw);
                if address_from_pubkey(&pk) != voter {
                    return Err("voter address mismatch".into());
                }
                // Signature scheme sanity check against the canonical bytes.
                if !verify(&a.voter_pubkey, &a.signing_bytes(), &a.signature) {
                    return Err("vote A signature invalid".into());
                }
                Ok(voter)
            }
        }
    }
}

/// A slash that was applied on chain, kept for explorers and audits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashRecord {
    pub id: String,
    pub offence: String,
    pub offender: String,
    /// Height the offence happened at.
    pub offence_height: u64,
    /// Height the punishment was applied at.
    pub applied_height: u64,
    pub burned: u128,
    pub bounty: u128,
    pub reporter: String,
    pub tombstoned: bool,
    pub jailed_until: u64,
}

/// Burn percentage for an equivocation: a floor, plus a correlation term based
/// on the offender's share of total stake. Capped at 100%.
pub fn equivocation_burn_pct(offender_stake: u128, total_stake: u128) -> u128 {
    if total_stake == 0 {
        return EQUIVOCATION_MIN_BURN_PCT;
    }
    let share_pct = offender_stake.saturating_mul(100) / total_stake;
    let correlated = share_pct.saturating_mul(EQUIVOCATION_CORRELATION_FACTOR);
    correlated.max(EQUIVOCATION_MIN_BURN_PCT).min(100)
}

/// Read-only validation of a report before it enters the mempool or a block.
pub fn check_report(store: &Store, height: u64, payload: &Option<Payload>) -> Result<Evidence, String> {
    let evidence = decode(payload)?;
    let offender = evidence.verify()?;
    if evidence.height() > height {
        return Err("evidence is from the future".into());
    }
    if height.saturating_sub(evidence.height()) > EVIDENCE_MAX_AGE_BLOCKS {
        return Err("evidence is too old to punish".into());
    }
    if store.slash(&evidence.id()).is_some() {
        return Err("this offence has already been slashed".into());
    }
    let acct = store.account(&offender);
    if acct.penalties.tombstoned {
        return Err("validator is already tombstoned".into());
    }
    if acct.staked == 0 && acct.unbonding_total() == 0 {
        return Err("offender has no stake left to slash".into());
    }
    Ok(evidence)
}

/// Apply an equivocation slash. Burns a share of the offender's bonded and
/// unbonding stake, pays the reporter a bounty out of the burn, and tombstones
/// the validator so it can never be elected again.
pub fn apply_report(
    store: &Store,
    height: u64,
    reporter: &str,
    evidence: &Evidence,
) -> Result<SlashRecord, String> {
    let offender = evidence.verify()?;
    if store.slash(&evidence.id()).is_some() {
        return Err("this offence has already been slashed".into());
    }
    let mut acct = store.account(&offender);
    if acct.penalties.tombstoned {
        return Err("validator is already tombstoned".into());
    }
    let total_stake = store.total_staked();
    let pct = equivocation_burn_pct(acct.staked, total_stake);

    // Unbonding stake is slashed too: exiting does not escape punishment.
    let mut burned = acct.staked * pct / 100;
    acct.staked -= burned;
    for u in acct.unbonding.iter_mut() {
        let cut = u.amount * pct / 100;
        u.amount -= cut;
        burned += cut;
    }
    acct.unbonding.retain(|u| u.amount > 0);
    acct.penalties.tombstoned = true;
    acct.penalties.jailed_until = TOMBSTONE_HEIGHT;
    acct.penalties.slashed += burned;
    store.set_account(&offender, &acct);

    let bounty = burned * REPORTER_BOUNTY_PCT / 100;
    if bounty > 0 && reporter != offender {
        let mut r = store.account(reporter);
        r.balance += bounty;
        store.set_account(reporter, &r);
    }

    let record = SlashRecord {
        id: evidence.id(),
        offence: evidence.label().to_string(),
        offender: offender.clone(),
        offence_height: evidence.height(),
        applied_height: height,
        burned,
        bounty,
        reporter: reporter.to_string(),
        tombstoned: true,
        jailed_until: TOMBSTONE_HEIGHT,
    };
    store.put_slash(&record);
    println!(
        "[slash] {} {} burned {} rai ({}% of stake) — tombstoned, reporter {} paid {} rai",
        record.offence, offender, burned, pct, reporter, bounty
    );
    Ok(record)
}

/// Leave a downtime jail. Only the validator itself can do this, only after the
/// jail expired, and never after a tombstone.
pub fn apply_unjail(store: &Store, height: u64, address: &str) -> Result<(), String> {
    let mut acct = store.account(address);
    if acct.penalties.tombstoned {
        return Err("tombstoned validators can never rejoin".into());
    }
    if acct.penalties.jailed_until == 0 {
        return Err("validator is not jailed".into());
    }
    if acct.penalties.jailed_until > height {
        return Err(format!(
            "still jailed for {} more blocks",
            acct.penalties.jailed_until - height
        ));
    }
    acct.penalties.jailed_until = 0;
    acct.penalties.missed_streak = 0;
    store.set_account(address, &acct);
    println!("[slash] {} left jail at #{}", address, height);
    Ok(())
}

/// Credit liveness for the validator that sealed `height`, and charge a missed
/// slot to every validator that was elected before it and stayed silent.
///
/// Derived purely from `(height, parent_hash, producer)`, so a node replaying
/// history reaches exactly the same liveness ledger as one that was online.
pub fn record_liveness(store: &Store, height: u64, parent_hash: &str, producer: &str) {
    if height < SLASHING_ACTIVATION_HEIGHT {
        return;
    }
    let set = crate::staking::validator_set_at(store, height);
    if set.len() < 2 {
        return; // a single validator can never be skipped
    }
    // The lowest attempt that elects this producer is the slot it actually used.
    let mut used: Option<u64> = None;
    for attempt in 0..crate::chain::MAX_LEADER_ATTEMPTS {
        match crate::staking::elect_leader_attempt(&set, height, parent_hash, attempt) {
            Some(leader) if leader == producer => {
                used = Some(attempt);
                break;
            }
            _ => {}
        }
    }
    let used = match used {
        Some(a) => a,
        None => return,
    };

    let mut missed: Vec<String> = Vec::new();
    for attempt in 0..used {
        if let Some(leader) = crate::staking::elect_leader_attempt(&set, height, parent_hash, attempt) {
            if leader != producer && !missed.contains(&leader) {
                missed.push(leader);
            }
        }
    }

    for address in missed {
        let mut acct = store.account(&address);
        acct.penalties.missed_slots += 1;
        acct.penalties.missed_streak += 1;
        if acct.penalties.missed_streak >= DOWNTIME_JAIL_STREAK && !acct.penalties.tombstoned {
            acct.penalties.missed_streak = 0;
            acct.penalties.downtime_jails += 1;
            acct.penalties.jailed_until = height + DOWNTIME_JAIL_BLOCKS;
            // First offence is a jail only. Repeat offenders also pay.
            let mut burned = 0u128;
            if acct.penalties.downtime_jails > 1 {
                burned = acct.staked * DOWNTIME_REPEAT_BURN_BPS / 10_000;
                acct.staked -= burned;
                acct.penalties.slashed += burned;
            }
            store.set_account(&address, &acct);
            store.put_slash(&SlashRecord {
                id: format!("downtime:{}:{}", height, address),
                offence: "downtime".into(),
                offender: address.clone(),
                offence_height: height,
                applied_height: height,
                burned,
                bounty: 0,
                reporter: String::new(),
                tombstoned: false,
                jailed_until: height + DOWNTIME_JAIL_BLOCKS,
            });
            println!(
                "[slash] {} jailed for downtime until #{} (burn {} rai)",
                address,
                height + DOWNTIME_JAIL_BLOCKS,
                burned
            );
        } else {
            store.set_account(&address, &acct);
        }
    }

    // Sealing a block clears the producer's streak.
    let mut p = store.account(producer);
    if p.penalties.missed_streak != 0 {
        p.penalties.missed_streak = 0;
        store.set_account(producer, &p);
    }
}

/// Hex-encoded JSON evidence rides in the transaction payload's `args` field,
/// so it is covered by the sender's signature like any other payload.
pub fn encode(evidence: &Evidence) -> Payload {
    Payload {
        args: hex::encode(serde_json::to_vec(evidence).unwrap_or_default()),
        ..Default::default()
    }
}

pub fn decode(payload: &Option<Payload>) -> Result<Evidence, String> {
    let p = payload.as_ref().ok_or("report carries no evidence")?;
    if p.args.is_empty() {
        return Err("report carries no evidence".into());
    }
    let raw = hex::decode(&p.args).map_err(|_| "evidence is not valid hex".to_string())?;
    if raw.len() > 64 * 1024 {
        return Err("evidence too large".into());
    }
    serde_json::from_slice(&raw).map_err(|e| format!("bad evidence: {}", e))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;
    use crate::types::txs_root;

    fn signed_header(kp: &Keypair, height: u64, state_root: &str) -> HeaderProof {
        let mut b = Block {
            height,
            parent_hash: "a".repeat(64),
            timestamp_ms: 1,
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
        HeaderProof::from_block(&b)
    }

    #[test]
    fn double_sign_is_provable() {
        let kp = Keypair::generate();
        let a = signed_header(&kp, 10, "aa");
        let b = signed_header(&kp, 10, "bb");
        let evidence = Evidence::Block { a, b };
        assert_eq!(evidence.verify().unwrap(), kp.address());
    }

    #[test]
    fn same_block_twice_is_not_evidence() {
        let kp = Keypair::generate();
        let a = signed_header(&kp, 10, "aa");
        let evidence = Evidence::Block { a: a.clone(), b: a };
        assert!(evidence.verify().is_err());
    }

    #[test]
    fn forged_header_is_rejected() {
        let kp = Keypair::generate();
        let mut a = signed_header(&kp, 10, "aa");
        let b = signed_header(&kp, 10, "bb");
        a.state_root = "cc".into(); // tampered after signing
        let evidence = Evidence::Block { a, b };
        assert!(evidence.verify().is_err());
    }

    #[test]
    fn double_vote_is_provable() {
        let kp = Keypair::generate();
        let mut a = crate::consensus::Vote {
            height: 7,
            hash: "one".into(),
            voter_pubkey: kp.pubkey_hex(),
            signature: String::new(),
        };
        a.signature = kp.sign_hex(&a.signing_bytes());
        let mut b = crate::consensus::Vote {
            height: 7,
            hash: "two".into(),
            voter_pubkey: kp.pubkey_hex(),
            signature: String::new(),
        };
        b.signature = kp.sign_hex(&b.signing_bytes());
        let evidence = Evidence::Vote { a, b };
        assert_eq!(evidence.verify().unwrap(), kp.address());
    }

    #[test]
    fn burn_is_correlated_with_stake_share() {
        // Small validator: floor applies.
        assert_eq!(equivocation_burn_pct(1_000, 100_000), 5);
        // Whale with 40% of stake: 3x correlation -> 120%, capped at 100%.
        assert_eq!(equivocation_burn_pct(40_000, 100_000), 100);
        // 10% share -> 30% burn.
        assert_eq!(equivocation_burn_pct(10_000, 100_000), 30);
    }
}
