//! Inazuma L1 node, as a library.
//!
//! The binary (`src/main.rs`) is a thin CLI over these modules. The library
//! target exists so fuzz targets and integration harnesses can call the wire
//! decoder and message dispatch directly, instead of re-implementing them.

#[cfg(test)]
mod battletest;
#[cfg(test)]
mod conformance;
#[cfg(test)]
mod fuzz;

pub mod chain;
pub mod consensus;
pub mod contracts;
pub mod crypto;
pub mod events;
pub mod fees;
pub mod journal;
pub mod limits;
pub mod log;
pub mod mempool;
pub mod metrics;
pub mod p2p;
pub mod poseidon;
pub mod qos;
pub mod rpc;
pub mod rpcauth;
pub mod shielded;
pub mod shielded_circuit;
pub mod signguard;
pub mod simulate;
pub mod slashing;
pub mod smt;
pub mod snapshot;
pub mod staking;
pub mod state;
pub mod tokens;
pub mod transport;
pub mod types;
pub mod ui;
pub mod ws;

#[cfg(feature = "byzantine")]
pub mod byzantine;

/// Blocks of history a pruning node keeps behind the finalized height.
/// ~2 days at 400 ms blocks: enough for peers to catch up, small on disk.
pub const DEFAULT_PRUNE_KEEP: u64 = 400_000;
