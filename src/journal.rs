//! Write journal: makes block execution atomic.
//!
//! Applying a block touches accounts, tokens, contracts and the Merkle tree
//! directly. If a later check fails (state root mismatch, invalid tx), those
//! writes must be undone — otherwise a node that rejects one block carries the
//! half-applied changes forward, computes a different state root on the next
//! attempt, and can never rejoin the network. That is a permanent, silent fork.
//!
//! Usage: `begin()`, run the block, then `commit()` on success or `rollback()`
//! on any failure. Only the value a key had *before* the block is remembered,
//! so repeated writes to one key cost one entry.
//!
//! Frames nest. A block opens an outer frame and every transaction inside it
//! opens its own, so one transaction that fails halfway through its writes is
//! undone on its own without discarding the transactions that already
//! succeeded. This matters because a failed transaction is *dropped* from the
//! block it was drafted into — if its partial writes survived, the producer's
//! state root would cover changes no importer can reproduce, and every peer
//! would reject the block as a state-root mismatch forever.

use sled::Tree;
use std::collections::HashMap;
use std::sync::Mutex;

type Key = (usize, Vec<u8>);
type Frame = HashMap<Key, Option<Vec<u8>>>;

#[derive(Default)]
pub struct Journal {
    /// Stack of savepoints. Empty means nothing is executing and writes pass
    /// straight through.
    frames: Mutex<Vec<Frame>>,
}

impl Journal {
    pub fn new() -> Self {
        Journal {
            frames: Mutex::new(Vec::new()),
        }
    }

    /// Open a savepoint.
    pub fn begin(&self) {
        self.frames.lock().unwrap().push(HashMap::new());
    }

    pub fn active(&self) -> bool {
        !self.frames.lock().unwrap().is_empty()
    }

    /// Keep the innermost savepoint's writes. Its undo entries are folded into
    /// the enclosing frame so an outer rollback still restores pre-block values.
    pub fn commit(&self) {
        let mut guard = self.frames.lock().unwrap();
        let Some(done) = guard.pop() else { return };
        if let Some(parent) = guard.last_mut() {
            for (key, before) in done {
                parent.entry(key).or_insert(before);
            }
        }
    }

    /// Record a key's value as it was when the innermost savepoint opened.
    pub fn record(&self, tree_id: usize, tree: &Tree, key: &[u8]) {
        let mut guard = self.frames.lock().unwrap();
        let Some(map) = guard.last_mut() else { return };
        let entry = (tree_id, key.to_vec());
        if !map.contains_key(&entry) {
            let before = tree.get(key).ok().flatten().map(|v| v.to_vec());
            map.insert(entry, before);
        }
    }

    /// Undo every write made since the innermost savepoint opened.
    pub fn rollback(&self, trees: &[&Tree]) {
        let taken = self.frames.lock().unwrap().pop();
        let Some(map) = taken else { return };
        for ((tree_id, key), before) in map {
            let Some(tree) = trees.get(tree_id) else {
                continue;
            };
            match before {
                Some(v) => {
                    let _ = tree.insert(key, v);
                }
                None => {
                    let _ = tree.remove(key);
                }
            }
        }
        for t in trees {
            let _ = t.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> (sled::Db, Tree) {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let t = db.open_tree("t").unwrap();
        (db, t)
    }

    #[test]
    fn inner_rollback_keeps_outer_writes() {
        let (_db, t) = tree();
        let j = Journal::new();

        j.begin(); // block
        j.record(0, &t, b"a");
        t.insert(b"a", b"1").unwrap();

        j.begin(); // tx that will fail
        j.record(0, &t, b"b");
        t.insert(b"b", b"2").unwrap();
        j.rollback(&[&t]);

        assert_eq!(t.get(b"a").unwrap().as_deref(), Some(&b"1"[..]));
        assert_eq!(
            t.get(b"b").unwrap(),
            None,
            "failed tx must leave nothing behind"
        );

        j.commit(); // block succeeds
        assert_eq!(t.get(b"a").unwrap().as_deref(), Some(&b"1"[..]));
    }

    #[test]
    fn outer_rollback_undoes_committed_inner_writes() {
        let (_db, t) = tree();
        t.insert(b"a", b"old").unwrap();
        let j = Journal::new();

        j.begin(); // block
        j.begin(); // tx
        j.record(0, &t, b"a");
        t.insert(b"a", b"new").unwrap();
        j.commit(); // tx succeeded
        j.rollback(&[&t]); // block rejected

        assert_eq!(t.get(b"a").unwrap().as_deref(), Some(&b"old"[..]));
    }

    #[test]
    fn writes_outside_any_frame_pass_through() {
        let (_db, t) = tree();
        let j = Journal::new();
        assert!(!j.active());
        j.record(0, &t, b"a");
        t.insert(b"a", b"1").unwrap();
        j.rollback(&[&t]);
        assert_eq!(t.get(b"a").unwrap().as_deref(), Some(&b"1"[..]));
    }
}
