//! Prometheus text-format metrics.
//!
//! Public testnet operators need machine-readable node health without an admin
//! key, but topology (peer addresses, node key) must stay out of it — the same
//! rule that redacts `inaz_netInfo` for anonymous callers. Everything here is
//! either already public in `inaz_chainInfo` or a plain counter.

use crate::chain::Node;
use std::sync::Arc;

fn line(out: &mut String, name: &str, help: &str, kind: &str, value: String) {
    out.push_str(&format!(
        "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
    ));
}

/// Render the whole node snapshot in Prometheus exposition format.
pub fn render(node: &Arc<Node>) -> String {
    let mut o = String::with_capacity(2048);
    let height = node.store.tip_height().unwrap_or(0);
    line(
        &mut o,
        "inazuma_block_height",
        "Height of the local chain tip.",
        "gauge",
        height.to_string(),
    );
    line(
        &mut o,
        "inazuma_finalized_height",
        "Highest finalized block height.",
        "gauge",
        node.store.finalized_height().to_string(),
    );
    line(
        &mut o,
        "inazuma_finality_lag_blocks",
        "Blocks between the tip and the last finalized block.",
        "gauge",
        height
            .saturating_sub(node.store.finalized_height())
            .to_string(),
    );
    line(
        &mut o,
        "inazuma_peer_count",
        "Connected P2P peers.",
        "gauge",
        node.peer_count().to_string(),
    );
    line(
        &mut o,
        "inazuma_mempool_txs",
        "Transactions queued in the mempool.",
        "gauge",
        node.mempool_size().to_string(),
    );
    line(
        &mut o,
        "inazuma_validators",
        "Active validators in the set.",
        "gauge",
        node.validators().len().to_string(),
    );
    line(
        &mut o,
        "inazuma_accounts",
        "Accounts in state.",
        "gauge",
        node.store.account_count().to_string(),
    );
    line(
        &mut o,
        "inazuma_txs_total",
        "Transactions executed since genesis.",
        "counter",
        node.store.tx_count().to_string(),
    );
    line(
        &mut o,
        "inazuma_tokens",
        "Tokens created.",
        "gauge",
        node.store.token_count().to_string(),
    );
    line(
        &mut o,
        "inazuma_contracts",
        "Contracts deployed.",
        "gauge",
        node.store.contract_count().to_string(),
    );
    line(
        &mut o,
        "inazuma_pruned_below",
        "Lowest retained block height.",
        "gauge",
        node.store.pruned_below().to_string(),
    );
    line(
        &mut o,
        "inazuma_halted",
        "1 when the node is halted by an operator.",
        "gauge",
        u8::from(node.halted()).to_string(),
    );
    line(
        &mut o,
        "inazuma_solo_mode",
        "1 when running without peers.",
        "gauge",
        u8::from(node.solo()).to_string(),
    );
    line(
        &mut o,
        "inazuma_base_fee_rai",
        "Current base fee in rai.",
        "gauge",
        node.base_fee().to_string(),
    );
    line(
        &mut o,
        "inazuma_total_supply_rai",
        "Total supply in rai.",
        "gauge",
        node.store.total_supply().to_string(),
    );
    line(
        &mut o,
        "inazuma_total_staked_rai",
        "Total bonded stake in rai.",
        "gauge",
        node.store.total_staked().to_string(),
    );
    // Fork detection needs a value alerting can compare across nodes. A hash is
    // not a number, so it ships as a label on a constant gauge — the standard
    // Prometheus "info metric" pattern.
    o.push_str("# HELP inazuma_state_root_info State root and tip hash at the local tip.\n");
    o.push_str("# TYPE inazuma_state_root_info gauge\n");
    o.push_str(&format!(
        "inazuma_state_root_info{{height=\"{}\",state_root=\"{}\",tip_hash=\"{}\",chain_id=\"{}\"}} 1\n",
        height,
        node.store.state_root_at(height),
        node.store.tip_hash(),
        node.genesis.chain_id,
    ));
    o
}

#[cfg(test)]
mod tests {
    #[test]
    fn help_and_type_precede_every_sample() {
        let mut s = String::new();
        super::line(&mut s, "x_total", "help text", "counter", "3".into());
        assert_eq!(
            s,
            "# HELP x_total help text\n# TYPE x_total counter\nx_total 3\n"
        );
    }
}
