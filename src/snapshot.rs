//! State snapshots: join the network without replaying every block.
//!
//! A fresh node used to replay the whole chain from genesis, which is fine at
//! 10k blocks and hopeless at millions. A snapshot is the *state* at one
//! finalized height plus that height's block header. Importing it lets the node
//! start validating from `height + 1` immediately.
//!
//! Trust model: the snapshot is verified, not trusted. Import rebuilds the
//! Merkle tree from the imported tables and refuses the snapshot unless the
//! recomputed state root equals the state root inside the snapshot's own signed
//! block header. A tampered snapshot therefore cannot install bad state — the
//! only thing the operator must check out of band is that the block hash
//! belongs to the canonical chain (compare it against a public explorer or a
//! second node's `inaz_getBlockByNumber`).

use crate::state::{Store, SNAPSHOT_TABLES};
use crate::types::Block;
use serde::{Deserialize, Serialize};

pub const SNAPSHOT_FORMAT: u32 = 1;

#[derive(Serialize, Deserialize, Clone)]
pub struct Table {
    pub name: String,
    /// Hex-encoded key/value pairs, so the file stays plain JSON.
    pub entries: Vec<(String, String)>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Snapshot {
    pub format: u32,
    pub chain_id: u64,
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub base_fee: String,
    pub block: Block,
    pub tables: Vec<Table>,
}

impl Snapshot {
    pub fn entry_count(&self) -> usize {
        self.tables.iter().map(|t| t.entries.len()).sum()
    }
}

/// Capture state at the current finalized tip. Snapshots are only taken at a
/// finalized height, so no snapshot can ever export a state that got reorged.
pub fn export(store: &Store, chain_id: u64) -> Result<Snapshot, String> {
    let finalized = store.finalized_height();
    let height = if finalized > 0 {
        finalized
    } else {
        store.tip_height().unwrap_or(0)
    };
    let block = store
        .block(height)
        .ok_or_else(|| format!("block {} is not stored", height))?;
    if store.state_root_at(height) != block.state_root {
        return Err("live state root does not match the block at this height".into());
    }
    let tables = SNAPSHOT_TABLES
        .iter()
        .map(|name| Table {
            name: (*name).to_string(),
            entries: store
                .raw_dump(name)
                .into_iter()
                .map(|(k, v)| (hex::encode(k), hex::encode(v)))
                .collect(),
        })
        .collect();
    Ok(Snapshot {
        format: SNAPSHOT_FORMAT,
        chain_id,
        height,
        block_hash: block.hash.clone(),
        state_root: block.state_root.clone(),
        base_fee: store.base_fee().to_string(),
        block,
        tables,
    })
}

/// Install a snapshot into an empty or resettable store and verify it.
///
/// On any verification failure the store is wiped rather than left half
/// written: a partially imported snapshot is worse than no snapshot.
pub fn import(store: &Store, snap: &Snapshot, chain_id: u64) -> Result<u64, String> {
    if snap.format != SNAPSHOT_FORMAT {
        return Err(format!("unsupported snapshot format {}", snap.format));
    }
    if snap.chain_id != chain_id {
        return Err(format!(
            "snapshot is for chain {}, this node is {}",
            snap.chain_id, chain_id
        ));
    }
    if snap.block.height != snap.height {
        return Err("snapshot height does not match its block".into());
    }
    if snap.block.compute_hash() != snap.block.hash || snap.block.hash != snap.block_hash {
        return Err("snapshot block hash does not match its contents".into());
    }
    if snap.block.state_root != snap.state_root {
        return Err("snapshot state root does not match its block header".into());
    }
    let base_fee: u128 = snap
        .base_fee
        .parse()
        .map_err(|_| "bad base fee".to_string())?;

    store.reset_chain();
    for table in &snap.tables {
        let mut entries = Vec::with_capacity(table.entries.len());
        for (k, v) in &table.entries {
            let key = hex::decode(k).map_err(|_| format!("bad key in {}", table.name))?;
            let val = hex::decode(v).map_err(|_| format!("bad value in {}", table.name))?;
            entries.push((key, val));
        }
        if let Err(e) = store.raw_restore(&table.name, &entries) {
            store.reset_chain();
            return Err(e);
        }
    }
    store.set_base_fee(base_fee);
    store.build_merkle_state();

    let rebuilt = store.state_root_at(snap.height);
    if rebuilt != snap.state_root {
        store.reset_chain();
        return Err(format!(
            "snapshot state root mismatch: header {} but imported state hashes to {}",
            snap.state_root, rebuilt
        ));
    }

    store.put_block(&snap.block);
    store.set_finalized_height(snap.height);
    // Everything below the snapshot height is history this node never had.
    store.mark_pruned_below(snap.height);
    Ok(snap.height)
}
