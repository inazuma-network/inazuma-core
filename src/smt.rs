//! Sparse Merkle tree over consensus state.
//!
//! Every piece of consensus state (accounts, tokens, token balances, contracts
//! and contract storage) is a leaf keyed by `sha256(domain|key)`. Updates cost
//! `DEPTH` hashes instead of a full-state rescan, and any node can hand a light
//! client an inclusion proof for a single account without shipping the world.
//!
//! Depth is 128 bits of the key hash: deep enough that two distinct keys
//! colliding is not a practical concern, shallow enough that a write is cheap.

use crate::crypto::sha256;
use sled::Tree;

pub const DEPTH: usize = 128;
const PATH_BYTES: usize = DEPTH / 8;

fn empty_hashes() -> &'static [[u8; 32]; DEPTH + 1] {
    use std::sync::OnceLock;
    static CELL: OnceLock<[[u8; 32]; DEPTH + 1]> = OnceLock::new();
    CELL.get_or_init(|| {
        let mut out = [[0u8; 32]; DEPTH + 1];
        for d in (0..DEPTH).rev() {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&out[d + 1]);
            buf[32..].copy_from_slice(&out[d + 1]);
            out[d] = sha256(&buf);
        }
        out
    })
}

pub fn empty_at(depth: usize) -> [u8; 32] {
    empty_hashes()[depth]
}

/// Domain-separated leaf key: the hash whose first `DEPTH` bits are the path.
pub fn leaf_key(domain: &str, key: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(domain.len() + key.len() + 1);
    buf.extend_from_slice(domain.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(key);
    sha256(&buf)
}

fn path_of(leaf_key: &[u8; 32]) -> [u8; PATH_BYTES] {
    let mut p = [0u8; PATH_BYTES];
    p.copy_from_slice(&leaf_key[..PATH_BYTES]);
    p
}

fn bit(path: &[u8; PATH_BYTES], index: usize) -> u8 {
    (path[index / 8] >> (7 - (index % 8))) & 1
}

fn flip(path: &[u8; PATH_BYTES], index: usize) -> [u8; PATH_BYTES] {
    let mut out = *path;
    out[index / 8] ^= 1 << (7 - (index % 8));
    out
}

/// Node identity: depth plus the path bits above that depth, everything below
/// masked off so a prefix can never be confused with a longer path.
fn node_id(depth: usize, path: &[u8; PATH_BYTES]) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + PATH_BYTES);
    key.push(depth as u8);
    let mut masked = *path;
    for i in depth..DEPTH {
        masked[i / 8] &= !(1 << (7 - (i % 8)));
    }
    key.extend_from_slice(&masked);
    key
}

fn parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    sha256(&buf)
}

/// Hash stored at a leaf. `None` (a deleted entry) collapses to the empty hash,
/// so removing a key leaves the same root as never having written it.
pub fn leaf_hash(key: &[u8; 32], value: Option<&[u8]>) -> [u8; 32] {
    match value {
        None => empty_at(DEPTH),
        Some(v) => {
            let mut buf = Vec::with_capacity(38 + v.len());
            buf.extend_from_slice(b"inzleaf|");
            buf.extend_from_slice(key);
            buf.push(b'|');
            buf.extend_from_slice(v);
            sha256(&buf)
        }
    }
}

pub struct Smt<'a> {
    pub nodes: &'a Tree,
}

impl<'a> Smt<'a> {
    pub fn new(nodes: &'a Tree) -> Self {
        Smt { nodes }
    }

    fn get_node(&self, depth: usize, path: &[u8; PATH_BYTES]) -> [u8; 32] {
        match self.nodes.get(node_id(depth, path)) {
            Ok(Some(v)) if v.len() == 32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(&v);
                h
            }
            _ => empty_at(depth),
        }
    }

    fn put_node(&self, depth: usize, path: &[u8; PATH_BYTES], hash: [u8; 32]) {
        let id = node_id(depth, path);
        if hash == empty_at(depth) {
            let _ = self.nodes.remove(id);
        } else {
            let _ = self.nodes.insert(id, hash.to_vec());
        }
    }

    /// Write (or clear) one leaf and rebuild the path to the root.
    pub fn set(&self, domain: &str, key: &[u8], value: Option<&[u8]>) {
        let lk = leaf_key(domain, key);
        let path = path_of(&lk);
        let mut cur = leaf_hash(&lk, value);
        self.put_node(DEPTH, &path, cur);
        for depth in (1..=DEPTH).rev() {
            let idx = depth - 1;
            let sib = self.get_node(depth, &flip(&path, idx));
            cur = if bit(&path, idx) == 0 {
                parent(&cur, &sib)
            } else {
                parent(&sib, &cur)
            };
            self.put_node(idx, &path, cur);
        }
    }

    pub fn root(&self) -> [u8; 32] {
        self.get_node(0, &[0u8; PATH_BYTES])
    }

    pub fn root_hex(&self) -> String {
        hex::encode(self.root())
    }

    /// Sibling hashes from the leaf up to the root, so a light client can
    /// recompute the root from one value. Default (empty) siblings are marked in
    /// the bitmap and omitted from the list to keep proofs small.
    pub fn proof(&self, domain: &str, key: &[u8]) -> (String, Vec<String>, String) {
        let lk = leaf_key(domain, key);
        let path = path_of(&lk);
        let mut bitmap = vec![0u8; PATH_BYTES];
        let mut siblings = Vec::new();
        for depth in (1..=DEPTH).rev() {
            let idx = depth - 1;
            let sib = self.get_node(depth, &flip(&path, idx));
            if sib != empty_at(depth) {
                bitmap[idx / 8] |= 1 << (7 - (idx % 8));
                siblings.push(hex::encode(sib));
            }
        }
        (hex::encode(lk), siblings, hex::encode(bitmap))
    }

    pub fn clear(&self) {
        let _ = self.nodes.clear();
    }
}

/// Reference verifier: recompute the root from a single leaf plus its proof.
/// This is the exact algorithm a light client or bridge contract must implement.
/// `value == None` proves non-inclusion (the leaf is empty).
pub fn verify_proof(
    root_hex: &str,
    domain: &str,
    key: &[u8],
    value: Option<&[u8]>,
    siblings_hex: &[String],
    bitmap_hex: &str,
) -> bool {
    let bitmap = match hex::decode(bitmap_hex) {
        Ok(b) if b.len() == PATH_BYTES => b,
        _ => return false,
    };
    let mut sibs = Vec::with_capacity(siblings_hex.len());
    for s in siblings_hex {
        match hex::decode(s) {
            Ok(b) if b.len() == 32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(&b);
                sibs.push(h);
            }
            _ => return false,
        }
    }
    let lk = leaf_key(domain, key);
    let mut path = [0u8; PATH_BYTES];
    path.copy_from_slice(&lk[..PATH_BYTES]);
    let mut cur = leaf_hash(&lk, value);
    let mut next = 0usize;
    for depth in (1..=DEPTH).rev() {
        let idx = depth - 1;
        let provided = (bitmap[idx / 8] >> (7 - (idx % 8))) & 1 == 1;
        let sib = if provided {
            if next >= sibs.len() {
                return false;
            }
            let s = sibs[next];
            next += 1;
            s
        } else {
            empty_at(depth)
        };
        cur = if bit(&path, idx) == 0 {
            parent(&cur, &sib)
        } else {
            parent(&sib, &cur)
        };
    }
    next == sibs.len() && hex::encode(cur) == root_hex.trim_start_matches("0x").to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> (sled::Db, Tree) {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let t = db.open_tree("smt").unwrap();
        (db, t)
    }

    #[test]
    fn proof_roundtrip() {
        let (_db, t) = tree();
        let smt = Smt::new(&t);
        smt.set("acct", b"alice", Some(b"100|0|0|0|0"));
        smt.set("acct", b"bob", Some(b"7|1|0|0|0"));
        let root = smt.root_hex();

        let (_lk, sibs, bm) = smt.proof("acct", b"alice");
        assert!(verify_proof(&root, "acct", b"alice", Some(b"100|0|0|0|0"), &sibs, &bm));
        // wrong value must fail
        assert!(!verify_proof(&root, "acct", b"alice", Some(b"999|0|0|0|0"), &sibs, &bm));

        // non-inclusion proof for an untouched key
        let (_lk, sibs, bm) = smt.proof("acct", b"carol");
        assert!(verify_proof(&root, "acct", b"carol", None, &sibs, &bm));
    }
}
