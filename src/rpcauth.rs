//! RPC access control: API keys, tiers, method classes and throttle policy.
//!
//! The public endpoint (rpc.inazuma.network) is the cheapest thing to attack on
//! the whole network: no stake, no signature, no cost. This module makes every
//! request answer three questions before it reaches the node — who is calling,
//! how expensive is the call, and has this caller already used its share.

use crate::limits::{secret_eq, KeyedLimiter, RateLimiter};
use crate::qos::StakeQos;
use crate::state::Store;
use std::collections::HashMap;
use std::net::IpAddr;

/// Anonymous (no key) budget. Generous for a wallet, fatal for a spam loop.
pub const ANON_RATE: f64 = 25.0;
pub const ANON_BURST: f64 = 100.0;
/// Budget for a request carrying a valid API key.
pub const KEY_RATE: f64 = 300.0;
pub const KEY_BURST: f64 = 1_200.0;
/// Per-sender transaction admission budget, in tx/s.
pub const ACCOUNT_TX_RATE: f64 = 50.0;
pub const ACCOUNT_TX_BURST: f64 = 200.0;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tier {
    /// No key presented.
    Anonymous,
    /// Valid API key: higher budget, still rate limited.
    Key,
    /// Operator key: higher budget plus access to privileged methods.
    Admin,
}

impl Tier {
    pub fn label(&self) -> &'static str {
        match self {
            Tier::Anonymous => "anon",
            Tier::Key => "key",
            Tier::Admin => "admin",
        }
    }
}

/// Methods only an operator key may call: they expose peer topology or act on
/// the node's own view of the network rather than on public chain data.
pub const PRIVILEGED_METHODS: &[&str] = &["inaz_netInfo", "inaz_rpcLimits"];

/// How much of a caller's budget a method spends. Reads that touch one key are
/// cheap; whole-tree walks, proofs and bulk submits are not.
pub fn method_cost(method: &str, params: &serde_json::Value) -> f64 {
    match method {
        "inaz_sendTransactions" => {
            let n = params.get("txs").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(1);
            // One unit per 50 transactions, so a 5,000-tx batch costs 100 units.
            2.0 + (n as f64 / 50.0)
        }
        "inaz_getProof" | "inaz_verifyProof" => 5.0,
        // Preflight runs the same checks as admission, so it is priced like one.
        "inaz_simulateTransaction" => 3.0,
        "inaz_signatureStatuses" => {
            let n = params.get("hashes").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(1);
            1.0 + (n as f64 / 25.0)
        }
        "inaz_subscribe" => 2.0,
        "inaz_tokenHoldings" | "inaz_contracts" | "inaz_contractStorage" | "inaz_tokens" => 4.0,
        "inaz_query" | "inaz_latestBlocks" | "inaz_validators" | "inaz_slashing" => 3.0,
        "inaz_sendTransaction" | "inaz_reportEquivocation" => 2.0,
        _ => 1.0,
    }
}

pub struct RpcConfig {
    /// Presented key -> tier. Empty means the endpoint is fully public.
    keys: HashMap<String, Tier>,
    /// When true, a request without a valid key is rejected with 401.
    pub require_auth: bool,
    /// Honour `X-Forwarded-For`. Only enable behind a proxy you control —
    /// otherwise a client can forge its own source IP and dodge the IP bucket.
    pub trust_proxy: bool,
    pub anon: RateLimiter,
    pub keyed: KeyedLimiter,
    pub accounts: KeyedLimiter,
    /// Stake-weighted capacity: keys bound to bonded accounts get a larger share.
    pub qos: StakeQos,
}

impl RpcConfig {
    pub fn new(keys: Vec<String>, admin_keys: Vec<String>, require_auth: bool, trust_proxy: bool) -> Self {
        RpcConfig::with_qos(keys, admin_keys, require_auth, trust_proxy, StakeQos::new(Vec::new()))
    }

    pub fn with_qos(
        keys: Vec<String>,
        admin_keys: Vec<String>,
        require_auth: bool,
        trust_proxy: bool,
        qos: StakeQos,
    ) -> Self {
        let mut map = HashMap::new();
        for k in keys {
            if k.len() >= 16 {
                map.insert(k, Tier::Key);
            }
        }
        for k in admin_keys {
            if k.len() >= 16 {
                map.insert(k, Tier::Admin);
            }
        }
        RpcConfig {
            // Requiring auth with no keys configured would brick the endpoint.
            require_auth: require_auth && !map.is_empty(),
            keys: map,
            trust_proxy,
            anon: RateLimiter::new(ANON_RATE, ANON_BURST),
            keyed: KeyedLimiter::new(KEY_RATE, KEY_BURST),
            accounts: KeyedLimiter::new(ACCOUNT_TX_RATE, ACCOUNT_TX_BURST),
            qos,
        }
    }

    pub fn public() -> Self {
        RpcConfig::new(Vec::new(), Vec::new(), false, false)
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    pub fn auth_enabled(&self) -> bool {
        !self.keys.is_empty()
    }

    /// Resolve a presented credential to a tier without leaking timing.
    pub fn tier_for(&self, presented: Option<&str>) -> Tier {
        let Some(p) = presented else { return Tier::Anonymous };
        let mut found = Tier::Anonymous;
        for (k, tier) in &self.keys {
            if secret_eq(k, p) {
                found = *tier;
            }
        }
        found
    }

    /// Charge one request against the right bucket. Keyed callers get their own
    /// budget so a busy dApp cannot be starved by anonymous traffic, and are
    /// still capped per IP to bound damage from a leaked key.
    pub fn charge(&self, ip: IpAddr, tier: Tier, credential: Option<&str>, cost: f64) -> bool {
        match tier {
            Tier::Anonymous => self.anon.allow_cost(ip, cost),
            Tier::Key | Tier::Admin => match credential {
                Some(c) => self.keyed.allow_cost(c, cost),
                None => self.anon.allow_cost(ip, cost),
            },
        }
    }

    /// Stake-weighted charge. A key bound to a bonded account spends its budget
    /// more slowly, in proportion to its share of stake and never beyond the
    /// hard multiplier cap. Anonymous callers are unaffected: priority has to be
    /// earned with coins, and it can never be taken by volume alone.
    pub fn charge_weighted(
        &self,
        store: &Store,
        ip: IpAddr,
        tier: Tier,
        credential: Option<&str>,
        cost: f64,
    ) -> bool {
        let effective = match tier {
            Tier::Anonymous => cost,
            _ => cost / self.qos.multiplier(store, credential).max(1.0),
        };
        self.charge(ip, tier, credential, effective)
    }

    /// Per-sender admission budget for transaction submission.
    pub fn charge_account(&self, address: &str, txs: usize) -> bool {
        self.accounts.allow_cost(address, txs.max(1) as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ip() -> IpAddr {
        "203.0.113.7".parse().unwrap()
    }

    #[test]
    fn tiers_and_auth_gate() {
        let cfg = RpcConfig::new(
            vec!["user-key-0123456789abcdef".into()],
            vec!["admin-key-0123456789abcdef".into()],
            true,
            false,
        );
        assert!(cfg.require_auth);
        assert_eq!(cfg.tier_for(None), Tier::Anonymous);
        assert_eq!(cfg.tier_for(Some("nope")), Tier::Anonymous);
        assert_eq!(cfg.tier_for(Some("user-key-0123456789abcdef")), Tier::Key);
        assert_eq!(cfg.tier_for(Some("admin-key-0123456789abcdef")), Tier::Admin);

        // require_auth cannot brick an endpoint that has no keys configured.
        assert!(!RpcConfig::new(vec![], vec![], true, false).require_auth);
    }

    #[test]
    fn anon_burst_is_bounded_and_batches_cost_more() {
        let cfg = RpcConfig::public();
        let mut allowed = 0;
        for _ in 0..(ANON_BURST as usize + 50) {
            if cfg.charge(ip(), Tier::Anonymous, None, 1.0) {
                allowed += 1;
            }
        }
        assert!(allowed <= ANON_BURST as usize + 2, "anon flood not bounded: {}", allowed);

        let big = json!({ "txs": vec![json!({}); 5_000] });
        assert!(method_cost("inaz_sendTransactions", &big) >= 100.0);
        assert_eq!(method_cost("inaz_blockNumber", &json!({})), 1.0);
    }

    #[test]
    fn account_throttle_stops_mempool_flood() {
        let cfg = RpcConfig::public();
        assert!(cfg.charge_account("abc", ACCOUNT_TX_BURST as usize));
        assert!(!cfg.charge_account("abc", ACCOUNT_TX_BURST as usize));
        // A different account is unaffected.
        assert!(cfg.charge_account("def", 1));
    }
}