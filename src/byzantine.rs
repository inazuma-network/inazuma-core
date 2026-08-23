//! Deliberately malicious node behaviour, compiled only with `--features byzantine`.
//!
//! In-process tests can assert that *given* two conflicting signed headers the
//! chain slashes the producer. They cannot tell you whether a real attacker,
//! running a real binary against real honest nodes over a real socket, gets
//! detected — gossip paths, evidence propagation and the honest chain's liveness
//! while under attack are all outside a unit test's reach. So the attacks ship
//! as a build of the node itself, driven by `INAZ_BYZANTINE`:
//!
//!   double-sign  seal the honest block, then forge a second, differently
//!                signed block at the same height and gossip both
//!   equivocate   same, but the forged block also carries a different tx set,
//!                so honest nodes see two conflicting state roots
//!   invalid      gossip a block whose state root is garbage but whose producer
//!                signature is valid — tests header-vs-execution validation
//!   withhold     never send a finality precommit — tests liveness under a
//!                silent validator
//!
//! Anything this module does is a slashable offence by design. The binary is
//! named `inazuma-byz` in the harness precisely so it can never be mistaken for
//! an operator build.

use crate::chain::Node;
use crate::p2p::{self, P2p};
use crate::types::{txs_root, Block};
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    DoubleSign,
    Equivocate,
    Invalid,
    Withhold,
}

/// Attack selected by `INAZ_BYZANTINE`; `None` means behave honestly.
pub fn mode() -> Option<Mode> {
    match std::env::var("INAZ_BYZANTINE").ok()?.trim() {
        "double-sign" | "doublesign" => Some(Mode::DoubleSign),
        "equivocate" => Some(Mode::Equivocate),
        "invalid" | "propose-invalid" => Some(Mode::Invalid),
        "withhold" | "withhold-vote" => Some(Mode::Withhold),
        other => {
            eprintln!("[byz] unknown INAZ_BYZANTINE={other:?}, behaving honestly");
            None
        }
    }
}

/// False only for the vote-withholding attack.
pub fn should_vote() -> bool {
    mode() != Some(Mode::Withhold)
}

pub fn banner() {
    if let Some(m) = mode() {
        eprintln!("[byz] ADVERSARIAL BUILD ACTIVE: {m:?} — this node will be slashed on purpose");
    }
}

/// Re-sign a header after mutation so `verify_producer()` still passes. Without
/// this the forgery is dropped as an unsigned block and never reaches the
/// slashing path, which would make the test pass for the wrong reason.
fn reseal(node: &Arc<Node>, mut b: Block) -> Block {
    b.signature = node.producer.sign_hex(&b.header_bytes());
    b.hash = b.compute_hash();
    b
}

/// Called right after the honest block was sealed and gossiped.
pub fn after_seal(node: &Arc<Node>, net: &Arc<P2p>, honest: &Block) {
    let Some(m) = mode() else { return };
    match m {
        Mode::Withhold => {}
        Mode::DoubleSign => {
            let mut evil = honest.clone();
            // Same height, same parent, same body — only the timestamp differs,
            // so the two headers are distinct and both validly signed. This is
            // the textbook equivocation an honest node must slash.
            evil.timestamp_ms = honest.timestamp_ms + 1;
            let evil = reseal(node, evil);
            eprintln!(
                "[byz] gossiping conflicting block #{} {}",
                evil.height,
                &evil.hash[..16]
            );
            p2p::announce_block(net, &evil);
        }
        Mode::Equivocate => {
            let mut evil = honest.clone();
            evil.timestamp_ms = honest.timestamp_ms + 1;
            // Drop the last transaction: the forged branch now has a different
            // tx root *and* claims the honest state root, so a peer that adopts
            // it would diverge. Detection must not depend on re-execution.
            if !evil.transactions.is_empty() {
                evil.transactions.pop();
            }
            evil.txs_root = txs_root(&evil.transactions);
            let evil = reseal(node, evil);
            eprintln!(
                "[byz] gossiping equivocating block #{} {}",
                evil.height,
                &evil.hash[..16]
            );
            p2p::announce_block(net, &evil);
        }
        Mode::Invalid => {
            let mut evil = honest.clone();
            evil.timestamp_ms = honest.timestamp_ms + 1;
            evil.state_root = "de".repeat(32);
            let evil = reseal(node, evil);
            eprintln!("[byz] gossiping invalid-state-root block #{}", evil.height);
            p2p::announce_block(net, &evil);
        }
    }
}
