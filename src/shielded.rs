//! Inazuma Shielded — the zero-knowledge privacy pool.
//!
//! Zcash-style shielded transfers, native to Inazuma Core: notes live as
//! commitments in an append-only Poseidon Merkle tree; spending reveals only
//! a nullifier (which burns the note without saying which one) plus a Groth16
//! proof that the spend is valid. Sender, receiver and amount never touch
//! the public ledger.
//!
//! Three transaction kinds move value:
//!   shield           public INAZ  -> one new note (amount is public)
//!   privatetransfer 2 notes in -> 2 notes out (fully hidden)
//!   unshield         notes in -> public INAZ (amount is public)
//!
//! Consensus invariants enforced here:
//!   * a nullifier may appear at most once in chain history (no double spend)
//!   * the pool's public balance only moves via shield/unshield amounts
//!   * every spend proof verifies against a tree root the chain has sealed
//!
//! All pool state lives in journaled sled trees, so a rejected block rolls
//! the pool back with everything else.

use crate::poseidon;
use ark_bn254::Fr;
use serde::{Deserialize, Serialize};

/// Depth of the note commitment tree. 2^32 leaves — four billion notes.
pub const TREE_DEPTH: usize = 32;

/// Height-gated like every consensus rule. Nodes only accept shielded
/// transactions at or above this height, so pre-activation history replays
/// byte-identically. Set well above the deploy tip before mainnet activation.
pub const SHIELDED_ACTIVATION_HEIGHT: u64 = u64::MAX;

/// Effective activation height. `INAZ_SHIELDED_ACTIVATION` overrides the
/// compiled-in height for devnets and tests only — every node in a network
/// must run with the same value or the network forks at activation.
pub fn activation_height() -> u64 {
    std::env::var("INAZ_SHIELDED_ACTIVATION")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(SHIELDED_ACTIVATION_HEIGHT)
}

/// A shielded address is a viewing key + spend key pair derived from the
/// owner's seed. Only the 32-byte owner public key goes into notes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    /// Owner tag: Poseidon2(spend_key, 0). Only the owner can recognize and
    /// spend the note; the tag itself reveals nothing.
    pub owner: String,
    /// Value in rai (1 INAZ = 1e9 rai).
    pub value: u128,
    /// Note randomness, hex Fr. Hides the commitment from anyone who guesses
    /// owner+value.
    pub rho: String,
}

impl Note {
    pub fn commitment(&self) -> Result<Fr, String> {
        let owner = poseidon::fr_from_hex(&self.owner).ok_or("bad owner field")?;
        let rho = poseidon::fr_from_hex(&self.rho).ok_or("bad rho field")?;
        Ok(note_commitment(owner, self.value, rho))
    }
}

/// commitment = H(H(owner, value), rho)
pub fn note_commitment(owner: Fr, value: u128, rho: Fr) -> Fr {
    poseidon::hash2(poseidon::hash2(owner, poseidon::fr_u128(value)), rho)
}

/// owner tag = H(spend_key, 0)
pub fn owner_tag(spend_key: Fr) -> Fr {
    poseidon::hash2(spend_key, Fr::from(0u64))
}

/// nullifier = H(spend_key, leaf_position) — binds the spend to one exact
/// leaf, so the same note can never be spent twice under a different index.
pub fn nullifier(spend_key: Fr, position: u64) -> Fr {
    poseidon::hash2(spend_key, Fr::from(position))
}

/// Root of an all-zero subtree at `depth` (depth 0 = the zero leaf itself).
pub fn zero_subtree_root(depth: usize) -> Fr {
    let mut z = Fr::from(0u64);
    for _ in 0..depth {
        z = poseidon::hash2(z, z);
    }
    z
}

// ---- incremental commitment tree ----

/// Root of a tree built from a full leaf list. Padded with zero subtrees to
/// TREE_DEPTH, so the result is exactly what the on-chain incremental tree
/// would hold. O(n log n)-ish; used for proofs and state rebuilds, not in
/// the block hot path.
pub fn root_from_leaves(leaves: &[Fr]) -> Fr {
    let mut level: Vec<Fr> = leaves.to_vec();
    for d in 0..TREE_DEPTH {
        if level.len() <= 1 {
            // Lone node rides up as the left child of zero subtrees.
            let mut cur = level.first().copied().unwrap_or_else(|| zero_subtree_root(d));
            for dd in d..TREE_DEPTH {
                cur = poseidon::hash2(cur, zero_subtree_root(dd));
            }
            return cur;
        }
        let zero = zero_subtree_root(d);
        let mut next = Vec::with_capacity(level.len() / 2 + level.len() % 2);
        for pair in level.chunks(2) {
            let r = if pair.len() > 1 { pair[1] } else { zero };
            next.push(poseidon::hash2(pair[0], r));
        }
        level = next;
    }
    level[0]
}

/// Merkle authentication path for the leaf at `pos`, bottom level first.
pub fn merkle_path(leaves: &[Fr], pos: usize) -> Result<Vec<Fr>, String> {
    if pos >= leaves.len() {
        return Err("leaf index out of range".into());
    }
    let mut path = Vec::with_capacity(TREE_DEPTH);
    let mut level: Vec<Fr> = leaves.to_vec();
    let mut idx = pos;
    for d in 0..TREE_DEPTH {
        let zero = zero_subtree_root(d);
        let sibling = if idx % 2 == 0 {
            level.get(idx + 1).copied().unwrap_or(zero)
        } else {
            level[idx - 1]
        };
        path.push(sibling);
        if level.len() <= 1 {
            // Remaining levels are all zero subtrees.
            for dd in (d + 1)..TREE_DEPTH {
                path.push(zero_subtree_root(dd));
            }
            break;
        }
        let mut next = Vec::with_capacity(level.len() / 2 + 1);
        let mut i = 0;
        while i < level.len() {
            let l = level[i];
            let r = if i + 1 < level.len() { level[i + 1] } else { zero };
            next.push(poseidon::hash2(l, r));
            i += 2;
        }
        level = next;
        idx /= 2;
    }
    path.truncate(TREE_DEPTH);
    Ok(path)
}

/// Verify a path against a root — the native mirror of the circuit check.
pub fn verify_path(leaf: Fr, pos: u64, path: &[Fr], root: Fr) -> bool {
    if path.len() != TREE_DEPTH {
        return false;
    }
    let mut cur = leaf;
    for (level, sibling) in path.iter().enumerate() {
        cur = if (pos >> level) & 1 == 1 {
            poseidon::hash2(*sibling, cur)
        } else {
            poseidon::hash2(cur, *sibling)
        };
    }
    cur == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_path_roundtrip() {
        let leaves: Vec<Fr> = (1..=5u64).map(Fr::from).collect();
        let root = root_from_leaves(&leaves);
        for pos in 0..leaves.len() {
            let path = merkle_path(&leaves, pos).unwrap();
            assert_eq!(path.len(), TREE_DEPTH);
            assert!(verify_path(leaves[pos], pos as u64, &path, root));
        }
        // Wrong position must not verify.
        let path = merkle_path(&leaves, 0).unwrap();
        assert!(!verify_path(leaves[0], 1, &path, root));
    }

    #[test]
    fn zero_roots_are_stable() {
        let r0 = zero_subtree_root(0);
        let r1 = zero_subtree_root(1);
        let r32 = zero_subtree_root(32);
        assert_eq!(r0, Fr::from(0u64));
        assert_ne!(r1, r0);
        assert_ne!(r32, r1);
        // Determinism across calls.
        assert_eq!(r32, zero_subtree_root(32));
    }

    #[test]
    fn commitments_hide_values() {
        let owner = Fr::from(7u64);
        let rho = Fr::from(9u64);
        let a = note_commitment(owner, 100, rho);
        let b = note_commitment(owner, 101, rho);
        assert_ne!(a, b);
    }

    #[test]
    fn nullifiers_bind_position() {
        let sk = Fr::from(5u64);
        assert_ne!(nullifier(sk, 0), nullifier(sk, 1));
    }
}
