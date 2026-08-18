//! Stake-weighted quality of service.
//!
//! A purely first-come endpoint is fair only to whoever spams hardest: an
//! anonymous loop and a real application share the same queue, so the
//! application loses. Here an API key can be *bound to an on-chain account*, and
//! the share of total bonded stake behind that account becomes the share of node
//! capacity reserved for it. Capacity is then something you commit coins to, not
//! something you take by shouting.
//!
//! Two properties matter and are enforced below:
//!   * A bound key can never be worse off than an unbound one (weight >= 1).
//!   * No single key can drain the node: the multiplier is hard-capped, so even
//!     100% of stake buys a bounded advantage, not an unlimited one.
//!
//! Binding is a claim by the operator of the endpoint, not a permission to move
//! funds: the key gets scheduling priority, never spending authority.

use crate::state::Store;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Ceiling on the advantage stake can buy, as a multiple of the base budget.
pub const MAX_STAKE_MULTIPLIER: f64 = 8.0;
/// How aggressively stake share converts into capacity share.
const SHARE_GAIN: f64 = 20.0;
/// Total-stake lookups are cached: it is a whole-tree walk, and it barely moves.
const CACHE_TTL: Duration = Duration::from_secs(5);

pub struct StakeQos {
    /// API key -> on-chain account whose stake backs it.
    bindings: HashMap<String, String>,
    cache: Mutex<Option<(u128, Instant)>>,
}

impl StakeQos {
    /// Parse `key:address` pairs. Malformed and short keys are ignored rather
    /// than silently granting priority to a typo.
    pub fn new(pairs: Vec<String>) -> Self {
        let mut bindings = HashMap::new();
        for pair in pairs {
            let Some((key, address)) = pair.split_once(':') else {
                continue;
            };
            let (key, address) = (key.trim(), address.trim());
            if key.len() >= 16 && crate::crypto::is_valid_address(address) {
                bindings.insert(key.to_string(), address.to_string());
            }
        }
        StakeQos {
            bindings,
            cache: Mutex::new(None),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    pub fn address_for(&self, credential: &str) -> Option<&String> {
        self.bindings
            .iter()
            .find(|(k, _)| crate::limits::secret_eq(k, credential))
            .map(|(_, a)| a)
    }

    fn total_staked(&self, store: &Store) -> u128 {
        let mut cache = self.cache.lock().unwrap();
        if let Some((total, at)) = *cache {
            if at.elapsed() < CACHE_TTL {
                return total;
            }
        }
        let total = store.total_staked();
        *cache = Some((total, Instant::now()));
        total
    }

    /// Budget multiplier for a credential: 1.0 when unbound or unstaked, up to
    /// `MAX_STAKE_MULTIPLIER` for a key backed by a large share of stake.
    pub fn multiplier(&self, store: &Store, credential: Option<&str>) -> f64 {
        if self.bindings.is_empty() {
            return 1.0;
        }
        let Some(cred) = credential else { return 1.0 };
        let Some(address) = self.address_for(cred) else {
            return 1.0;
        };
        let total = self.total_staked(store);
        if total == 0 {
            return 1.0;
        }
        let staked = store.account(address).staked;
        if staked == 0 {
            return 1.0;
        }
        let share = (staked as f64) / (total as f64);
        (1.0 + share * SHARE_GAIN).clamp(1.0, MAX_STAKE_MULTIPLIER)
    }

    /// Stake share as a percentage, for reporting over RPC.
    pub fn share_pct(&self, store: &Store, credential: Option<&str>) -> f64 {
        let Some(cred) = credential else { return 0.0 };
        let Some(address) = self.address_for(cred) else {
            return 0.0;
        };
        let total = self.total_staked(store);
        if total == 0 {
            return 0.0;
        }
        (store.account(address).staked as f64) / (total as f64) * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_well_formed_bindings_are_accepted() {
        let qos = StakeQos::new(vec![
            "short:abc".into(),
            "key-0123456789abcdef:not-an-address".into(),
            "no-separator".into(),
        ]);
        assert!(
            qos.is_empty(),
            "a malformed binding must never grant priority"
        );
    }

    #[test]
    fn unbound_keys_get_the_base_budget() {
        let qos = StakeQos::new(Vec::new());
        assert_eq!(qos.len(), 0);
        // With no bindings configured every caller is equal.
        assert!(qos.address_for("anything").is_none());
    }
}
