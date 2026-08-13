//! Shared abuse limits for the public-facing RPC and the P2P port.
//!
//! Both listeners used to spawn an unbounded thread per connection and accept
//! unbounded payloads, so one host could exhaust the node's memory and threads
//! for free. These are the cheap, dependency-free guards.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// Per-IP token bucket: sustained `rate` requests per second with `burst` slack.
pub struct RateLimiter {
    rate: f64,
    burst: f64,
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
}

impl RateLimiter {
    pub fn new(rate: f64, burst: f64) -> Self {
        RateLimiter { rate, burst, buckets: Mutex::new(HashMap::new()) }
    }

    pub fn allow(&self, ip: IpAddr) -> bool {
        self.allow_cost(ip, 1.0)
    }

    /// Weighted variant: an expensive call spends more of the bucket than a
    /// cheap one, so a proof or bulk-submit flood costs the caller its quota.
    pub fn allow_cost(&self, ip: IpAddr, cost: f64) -> bool {
        let now = Instant::now();
        let mut map = self.buckets.lock().unwrap();
        // Keep the table from growing without bound under a spoofed-IP flood.
        if map.len() > 20_000 {
            map.retain(|_, (_, seen)| now.duration_since(*seen).as_secs() < 60);
        }
        let entry = map.entry(ip).or_insert((self.burst, now));
        let elapsed = now.duration_since(entry.1).as_secs_f64();
        entry.1 = now;
        entry.0 = (entry.0 + elapsed * self.rate).min(self.burst);
        if entry.0 >= cost {
            entry.0 -= cost;
            true
        } else {
            false
        }
    }
}

/// Token bucket keyed by an arbitrary string: API keys and sender addresses.
/// The IP bucket alone is not enough — one key behind many IPs, or one account
/// spamming nonces from a botnet, both slip past a purely per-IP limit.
pub struct KeyedLimiter {
    rate: f64,
    burst: f64,
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
}

impl KeyedLimiter {
    pub fn new(rate: f64, burst: f64) -> Self {
        KeyedLimiter { rate, burst, buckets: Mutex::new(HashMap::new()) }
    }

    pub fn allow_cost(&self, key: &str, cost: f64) -> bool {
        let now = Instant::now();
        let mut map = self.buckets.lock().unwrap();
        if map.len() > 50_000 {
            map.retain(|_, (_, seen)| now.duration_since(*seen).as_secs() < 120);
        }
        let entry = map.entry(key.to_string()).or_insert((self.burst, now));
        let elapsed = now.duration_since(entry.1).as_secs_f64();
        entry.1 = now;
        entry.0 = (entry.0 + elapsed * self.rate).min(self.burst);
        if entry.0 >= cost {
            entry.0 -= cost;
            true
        } else {
            false
        }
    }

    pub fn tracked(&self) -> usize {
        self.buckets.lock().unwrap().len()
    }
}

/// Constant-time string compare, so probing an API key byte by byte gains
/// nothing from response timing.
pub fn secret_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Counts live connections so a listener can refuse work instead of falling over.
pub struct ConnGuard {
    live: AtomicUsize,
    max: usize,
}

pub struct ConnTicket<'a>(&'a ConnGuard);

impl ConnGuard {
    pub fn new(max: usize) -> Self {
        ConnGuard { live: AtomicUsize::new(0), max }
    }

    pub fn try_acquire(&self) -> Option<ConnTicket<'_>> {
        let mut cur = self.live.load(Ordering::Relaxed);
        loop {
            if cur >= self.max {
                return None;
            }
            match self.live.compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::Relaxed) {
                Ok(_) => return Some(ConnTicket(self)),
                Err(actual) => cur = actual,
            }
        }
    }

    pub fn live(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }
}

impl Drop for ConnTicket<'_> {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Reputation for P2P peers: misbehaviour costs score, and a peer that runs out
/// is refused for a cooling-off period instead of being trusted forever.
pub struct PeerBook {
    scores: Mutex<HashMap<IpAddr, (i32, Option<Instant>)>>,
    /// Verified node identities seen per IP. Handshake-authenticated identities
    /// are what let an operator tell a real validator from a sybil on the same
    /// subnet, and they keep the connection log readable.
    identities: Mutex<HashMap<IpAddr, String>>,
    ban_secs: u64,
}

impl PeerBook {
    pub fn new(ban_secs: u64) -> Self {
        PeerBook {
            scores: Mutex::new(HashMap::new()),
            identities: Mutex::new(HashMap::new()),
            ban_secs,
        }
    }

    pub fn is_banned(&self, ip: IpAddr) -> bool {
        let mut map = self.scores.lock().unwrap();
        match map.get(&ip) {
            Some((_, Some(until))) => {
                if Instant::now() < *until {
                    true
                } else {
                    map.insert(ip, (0, None));
                    false
                }
            }
            _ => false,
        }
    }

    pub fn reward(&self, ip: IpAddr) {
        let mut map = self.scores.lock().unwrap();
        let e = map.entry(ip).or_insert((0, None));
        e.0 = (e.0 + 1).min(100);
    }

    /// Returns true when the peer just got banned.
    pub fn penalize(&self, ip: IpAddr, cost: i32) -> bool {
        let mut map = self.scores.lock().unwrap();
        let e = map.entry(ip).or_insert((0, None));
        e.0 -= cost;
        if e.0 <= -100 {
            e.0 = 0;
            e.1 = Some(Instant::now() + std::time::Duration::from_secs(self.ban_secs));
            return true;
        }
        false
    }

    /// Record the authenticated node key for an IP. Returns true the first time
    /// this pairing is seen, so callers can log once instead of every session.
    pub fn note_identity(&self, ip: IpAddr, id: &str) -> bool {
        let mut map = self.identities.lock().unwrap();
        match map.get(&ip) {
            Some(known) if known == id => false,
            _ => {
                map.insert(ip, id.to_string());
                true
            }
        }
    }

    pub fn known_identities(&self) -> Vec<(IpAddr, String)> {
        self.identities.lock().unwrap().iter().map(|(k, v)| (*k, v.clone())).collect()
    }

    pub fn banned_count(&self) -> usize {
        let now = Instant::now();
        self.scores
            .lock()
            .unwrap()
            .values()
            .filter(|(_, until)| until.map(|u| u > now).unwrap_or(false))
            .count()
    }
}

/// Live inbound connections per remote IP. The global cap alone lets a single
/// host fill every slot and eclipse the node; this bounds each host's share.
pub struct IpConnCounter {
    live: Mutex<HashMap<IpAddr, usize>>,
    max_per_ip: usize,
}

pub struct IpTicket<'a> {
    counter: &'a IpConnCounter,
    ip: IpAddr,
}

impl IpConnCounter {
    pub fn new(max_per_ip: usize) -> Self {
        IpConnCounter { live: Mutex::new(HashMap::new()), max_per_ip }
    }

    pub fn try_acquire(&self, ip: IpAddr) -> Option<IpTicket<'_>> {
        let mut map = self.live.lock().unwrap();
        let slot = map.entry(ip).or_insert(0);
        if *slot >= self.max_per_ip {
            return None;
        }
        *slot += 1;
        Some(IpTicket { counter: self, ip })
    }

    pub fn live_for(&self, ip: IpAddr) -> usize {
        self.live.lock().unwrap().get(&ip).copied().unwrap_or(0)
    }
}

impl Drop for IpTicket<'_> {
    fn drop(&mut self) {
        let mut map = self.counter.live.lock().unwrap();
        if let Some(slot) = map.get_mut(&self.ip) {
            *slot = slot.saturating_sub(1);
            if *slot == 0 {
                map.remove(&self.ip);
            }
        }
    }
}
