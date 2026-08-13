//! Fee market.
//!
//! Until now every transaction paid the same flat `MIN_FEE`, which means a
//! spammer pays the same as a user in a congested block and there is nothing to
//! price scarce block space with. From `FEE_MARKET_ACTIVATION_HEIGHT` the network
//! carries a base fee that rises when blocks run above target and decays when
//! they run below, exactly like EIP-1559's controller but derived from block
//! history so it needs no new header field and no hard fork of the block format.

use crate::chain::MAX_TXS_PER_BLOCK;
use crate::types::MIN_FEE;

/// Height at which the base fee becomes a consensus rule. Set ahead of the live
/// tip so every node upgrades and replays existing history unchanged.
pub const FEE_MARKET_ACTIVATION_HEIGHT: u64 = 200_000;
/// Blocks aim for half-full, leaving headroom for bursts.
pub const TARGET_TXS_PER_BLOCK: usize = MAX_TXS_PER_BLOCK / 2;
/// Maximum move per block, in percent — the same 12.5% damping Ethereum uses.
pub const MAX_CHANGE_PCT: u128 = 12;
/// Hard ceiling so a runaway controller can never price the chain out.
pub const MAX_BASE_FEE: u128 = 1_000_000_000; // 1 INAZ

/// Base fee for the block after one that carried `txs` transactions.
pub fn next_base_fee(prev: u128, txs: usize) -> u128 {
    let prev = prev.max(MIN_FEE);
    let target = TARGET_TXS_PER_BLOCK as u128;
    let used = txs as u128;
    let step = (prev * MAX_CHANGE_PCT / 100).max(1);
    let next = if used > target {
        let over = used - target;
        prev + step * over / target
    } else if used < target {
        let under = target - used;
        prev.saturating_sub(step * under / target)
    } else {
        prev
    };
    next.clamp(MIN_FEE, MAX_BASE_FEE)
}

/// Fee floor a transaction must pay to be admitted at `height`.
pub fn required_fee(height: u64, base_fee: u128) -> u128 {
    if height < FEE_MARKET_ACTIVATION_HEIGHT {
        MIN_FEE
    } else {
        base_fee.max(MIN_FEE)
    }
}
