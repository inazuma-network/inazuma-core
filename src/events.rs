//! Push notifications for the node.
//!
//! Polling is the reason a "fast" endpoint still feels slow: a client asking
//! "is it in yet?" every 200 ms learns about a block on average half a block
//! late, and costs the node a full request each time. This module lets the node
//! push the moment state changes, so a wallet, indexer or trading bot reacts in
//! the same tick the block is sealed.
//!
//! The bus is deliberately dumb and non-blocking. Each subscriber owns a bounded
//! queue; a consumer that stops reading fills its queue and is dropped instead of
//! stalling block production. Nothing here can ever slow down consensus.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Mutex;

/// Queue depth per subscription. Deep enough to absorb a burst of blocks, small
/// enough that a dead consumer cannot hold memory hostage.
const QUEUE_DEPTH: usize = 256;
/// Consecutive failed sends tolerated before a subscription is considered dead.
const MAX_LAG_STRIKES: u32 = 3;
/// Upper bound on live subscriptions across all connections.
pub const MAX_SUBSCRIPTIONS: usize = 4_096;
/// Upper bound per connection, so one socket cannot take the whole table.
pub const MAX_SUBS_PER_CONN: usize = 64;

/// Channels a client may subscribe to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Channel {
    /// Every new block header, produced locally or imported from a peer.
    Heads,
    /// Fires when the finalized height advances.
    Finality,
    /// Every transaction admitted to this node's pool, before inclusion.
    Mempool,
    /// One specific transaction hash, until it is included.
    Signature(String),
    /// Any block touching this address, with its post-block balance and nonce.
    Account(String),
    /// Contract activity; `None` means every contract.
    Logs(Option<String>),
}

impl Channel {
    pub fn label(&self) -> &'static str {
        match self {
            Channel::Heads => "heads",
            Channel::Finality => "finality",
            Channel::Mempool => "mempool",
            Channel::Signature(_) => "signature",
            Channel::Account(_) => "account",
            Channel::Logs(_) => "logs",
        }
    }

    /// Parse a subscription request. Filters are mandatory where a missing filter
    /// would turn a cheap subscription into a firehose of every account update.
    pub fn parse(channel: &str, params: &Value) -> Result<Channel, String> {
        let get = |k: &str| {
            params
                .get(k)
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
        };
        match channel {
            "heads" | "newHeads" => Ok(Channel::Heads),
            "finality" => Ok(Channel::Finality),
            "mempool" | "pending" => Ok(Channel::Mempool),
            "signature" => {
                let h = get("hash").ok_or("signature subscription needs a hash")?;
                if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err("hash must be 32 bytes of hex".into());
                }
                Ok(Channel::Signature(h.to_lowercase()))
            }
            "account" => {
                let a = get("address").ok_or("account subscription needs an address")?;
                if !crate::crypto::is_valid_address(&a) {
                    return Err("invalid address".into());
                }
                Ok(Channel::Account(a))
            }
            "logs" => Ok(Channel::Logs(get("contract"))),
            other => Err(format!("unknown channel '{}'", other)),
        }
    }

    /// Does this event belong to this subscription?
    fn matches(&self, ev: &Event) -> bool {
        match self {
            Channel::Heads => ev.channel == "heads",
            Channel::Finality => ev.channel == "finality",
            Channel::Mempool => ev.channel == "mempool",
            Channel::Signature(h) => ev.channel == "signature" && ev.key.as_deref() == Some(h),
            Channel::Account(a) => ev.channel == "account" && ev.key.as_deref() == Some(a),
            Channel::Logs(None) => ev.channel == "logs",
            Channel::Logs(Some(c)) => ev.channel == "logs" && ev.key.as_deref() == Some(c),
        }
    }
}

pub struct Event {
    pub channel: &'static str,
    /// Routing key: the hash, address or contract the event is about.
    pub key: Option<String>,
    pub payload: Value,
}

impl Event {
    pub fn new(channel: &'static str, key: Option<String>, payload: Value) -> Self {
        Event {
            channel,
            key,
            payload,
        }
    }
}

struct Sub {
    channel: Channel,
    conn: u64,
    tx: SyncSender<String>,
    strikes: u32,
}

#[derive(Default)]
pub struct EventBus {
    subs: Mutex<HashMap<u64, Sub>>,
    next_id: AtomicU64,
}

impl EventBus {
    pub fn new() -> Self {
        EventBus::default()
    }

    pub fn len(&self) -> usize {
        self.subs.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Register a subscription. `conn` groups subscriptions belonging to one
    /// socket so they can all be dropped when it closes.
    pub fn subscribe(
        &self,
        conn: u64,
        channel: Channel,
        sender: &SubSender,
    ) -> Result<u64, String> {
        let mut subs = self.subs.lock().unwrap();
        if subs.len() >= MAX_SUBSCRIPTIONS {
            return Err("subscription table full".into());
        }
        if subs.values().filter(|s| s.conn == conn).count() >= MAX_SUBS_PER_CONN {
            return Err("too many subscriptions on this connection".into());
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        subs.insert(
            id,
            Sub {
                channel,
                conn,
                tx: sender.0.clone(),
                strikes: 0,
            },
        );
        Ok(id)
    }

    /// Cancel one subscription. Only the connection that created it may do so,
    /// otherwise any client could silence another client's stream.
    pub fn unsubscribe(&self, conn: u64, id: u64) -> bool {
        let mut subs = self.subs.lock().unwrap();
        match subs.get(&id) {
            Some(s) if s.conn == conn => {
                subs.remove(&id);
                true
            }
            _ => false,
        }
    }

    pub fn drop_conn(&self, conn: u64) {
        self.subs.lock().unwrap().retain(|_, s| s.conn != conn);
    }

    /// Fan an event out to matching subscribers. Never blocks: a subscriber whose
    /// queue is full takes a strike, and is removed once it is clearly gone.
    pub fn publish(&self, ev: Event) {
        let mut subs = self.subs.lock().unwrap();
        if subs.is_empty() {
            return;
        }
        let mut dead: Vec<u64> = Vec::new();
        for (id, sub) in subs.iter_mut() {
            if !sub.channel.matches(&ev) {
                continue;
            }
            let frame = json!({
                "jsonrpc": "2.0",
                "method": "inaz_subscription",
                "params": { "subscription": id, "channel": sub.channel.label(), "result": ev.payload },
            })
            .to_string();
            match sub.tx.try_send(frame) {
                Ok(()) => sub.strikes = 0,
                Err(TrySendError::Full(_)) => {
                    sub.strikes += 1;
                    if sub.strikes >= MAX_LAG_STRIKES {
                        dead.push(*id);
                    }
                }
                Err(TrySendError::Disconnected(_)) => dead.push(*id),
            }
        }
        for id in dead {
            subs.remove(&id);
        }
    }
}

/// Sending half of a connection's delivery queue. Cloneable, so subscriptions can
/// still be registered after the socket's writer thread has taken the receiver.
#[derive(Clone)]
pub struct SubSender(SyncSender<String>);

/// Create a delivery queue for one connection: keep the sender for registration,
/// move the receiver into the thread that owns the socket.
pub fn queue() -> (SubSender, Receiver<String>) {
    let (tx, rx) = sync_channel(QUEUE_DEPTH);
    (SubSender(tx), rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_only_matching_events() {
        let bus = EventBus::new();
        let (tx, rx) = queue();
        let id = bus.subscribe(1, Channel::Heads, &tx).unwrap();
        bus.publish(Event::new("heads", None, json!({ "height": 7 })));
        bus.publish(Event::new("mempool", None, json!({ "hash": "x" })));
        let got = rx.try_recv().unwrap();
        assert!(got.contains("\"height\":7"));
        assert!(rx.try_recv().is_err(), "unrelated channel leaked through");
        assert!(bus.unsubscribe(1, id));
        assert!(!bus.unsubscribe(1, id));
    }

    #[test]
    fn filters_are_enforced_and_scoped_per_connection() {
        assert!(Channel::parse("account", &json!({})).is_err());
        assert!(Channel::parse("signature", &json!({ "hash": "zz" })).is_err());
        assert!(Channel::parse("nope", &json!({})).is_err());

        let bus = EventBus::new();
        let (tx, rx) = queue();
        let id = bus
            .subscribe(1, Channel::Signature("ab".repeat(32)), &tx)
            .unwrap();
        // A different connection cannot cancel someone else's subscription.
        assert!(!bus.unsubscribe(2, id));
        bus.publish(Event::new("signature", Some("cd".repeat(32)), json!({})));
        assert!(rx.try_recv().is_err());
        bus.publish(Event::new("signature", Some("ab".repeat(32)), json!({})));
        assert!(rx.try_recv().is_ok());
        bus.drop_conn(1);
        assert!(bus.is_empty());
    }

    #[test]
    fn slow_consumer_is_dropped_not_tolerated_forever() {
        let bus = EventBus::new();
        let (tx, rx) = queue();
        bus.subscribe(1, Channel::Heads, &tx).unwrap();
        for i in 0..(QUEUE_DEPTH + MAX_LAG_STRIKES as usize + 8) {
            bus.publish(Event::new("heads", None, json!({ "height": i })));
        }
        assert!(
            bus.is_empty(),
            "a consumer that never reads must be evicted"
        );
    }
}
