//! Inazuma peer-to-peer layer: block, transaction and vote gossip over raw TCP.
//!
//! Wire format is one JSON object per line, so it can be read by hand with netcat
//! and needs no schema registry. Messages:
//!   {"t":"block","block":{...}}      a freshly sealed block
//!   {"t":"tx","tx":{...}}            a pending transaction
//!   {"t":"vote","vote":{...}}        a finality precommit
//!   {"t":"status"}                   -> {"t":"statusres",...}
//!   {"t":"getblocks","from":N}       -> {"t":"blocks","blocks":[...]}

use crate::chain::Node;
use crate::consensus::Vote;
use crate::crypto::Keypair;
use crate::limits::{ConnGuard, IpConnCounter, PeerBook, RateLimiter};
use crate::slashing::Evidence;
use crate::transport::{self, Channel, MAGIC};
use crate::types::{Block, Transaction};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::Read;
use std::net::{IpAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const MAX_SYNC_BATCH: u64 = 200;
/// Only one catch-up may run at a time. Concurrent syncs used to fetch
/// overlapping ranges from different peers, so one thread's batch went stale the
/// moment the other imported a block — surfacing as a bogus "parent hash
/// mismatch" that then triggered a full replay from genesis.
static SYNC_GATE: Mutex<()> = Mutex::new(());
/// Unix seconds of the last genesis replay, so a node that keeps diverging
/// cannot spin in a reset loop and never finish syncing.
static LAST_RESET: AtomicU64 = AtomicU64::new(0);
/// A full replay is expensive; never start another within this window.
const RESET_COOLDOWN_SECS: u64 = 900;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
/// Abuse limits for the gossip port: peers are few, messages are many.
const P2P_MSGS_PER_SEC: f64 = 400.0;
const P2P_BURST: f64 = 2_000.0;
const P2P_MAX_LIVE_CONNS: usize = 128;
const P2P_BAN_SECS: u64 = 600;
/// Score cost of a message that could not possibly come from an honest peer.
const COST_BAD_MESSAGE: i32 = 12;
const COST_BAD_BLOCK: i32 = 20;
/// An unauthenticated (legacy plaintext) peer starts in the red: it can still
/// sync during a rolling upgrade, but it burns its budget much faster.
const COST_PLAINTEXT: i32 = 4;
/// Eclipse resistance: no single host may occupy more than this many inbound
/// slots, so one machine cannot fill the table with sybil connections.
const P2P_MAX_CONNS_PER_IP: usize = 8;

pub struct P2p {
    pub listen: String,
    pub peers: Vec<String>,
    /// Reputation per remote IP; repeat offenders get banned for a while.
    pub book: PeerBook,
    /// This node's ed25519 identity, used to authenticate the encrypted channel.
    pub id: Arc<Keypair>,
    /// When non-empty, only these hex node keys may connect or be dialled. This
    /// is the hard anti-eclipse setting for validators.
    pub allowed_ids: HashSet<String>,
    /// Refuse plaintext peers entirely (set once every node has upgraded).
    pub require_encryption: bool,
}

impl P2p {
    pub fn new(listen: String, peers: Vec<String>, id: Arc<Keypair>) -> Self {
        P2p {
            listen,
            peers,
            book: PeerBook::new(P2P_BAN_SECS),
            id,
            allowed_ids: HashSet::new(),
            require_encryption: false,
        }
    }

    pub fn with_allowlist(mut self, ids: HashSet<String>) -> Self {
        self.allowed_ids = ids;
        self
    }

    pub fn with_required_encryption(mut self, required: bool) -> Self {
        self.require_encryption = required;
        self
    }

    /// Static peers are never evicted by connection pressure: an attacker that
    /// floods the listener still cannot squeeze out the configured validators.
    fn is_static_peer(&self, ip: IpAddr) -> bool {
        self.peers.iter().any(|p| {
            p.trim()
                .to_socket_addrs()
                .map(|mut it| it.any(|a| a.ip() == ip))
                .unwrap_or(false)
        })
    }

    fn id_allowed(&self, peer_id: Option<&str>) -> bool {
        if self.allowed_ids.is_empty() {
            return true;
        }
        match peer_id {
            Some(id) => self.allowed_ids.contains(id),
            None => false,
        }
    }

    /// Open an authenticated encrypted channel to a peer, falling back to legacy
    /// plaintext only when encryption is not required.
    pub fn dial(&self, peer: &str) -> Result<Channel, String> {
        let stream = connect(peer)?;
        match transport::handshake_initiator(stream, &self.id) {
            Ok(ch) => {
                if !self.id_allowed(ch.peer_id()) {
                    return Err(format!("peer {} is not on the allowlist", peer));
                }
                Ok(ch)
            }
            Err(e) => {
                if self.require_encryption {
                    Err(format!("encrypted handshake with {} failed: {}", peer, e))
                } else {
                    transport::plain_channel(connect(peer)?, Vec::new())
                }
            }
        }
    }

    /// Send one message to every peer, best effort. A peer being down is normal.
    pub fn broadcast(self: &Arc<Self>, msg: &Value) {
        for peer in &self.peers {
            let peer = peer.clone();
            let msg = msg.clone();
            let me = Arc::clone(self);
            std::thread::spawn(move || {
                if let Ok(mut ch) = me.dial(&peer) {
                    let _ = ch.send(&msg);
                }
            });
        }
    }

    /// Send one request and read a single reply, over the encrypted channel.
    pub fn request(self: &Arc<Self>, peer: &str, msg: &Value) -> Result<Value, String> {
        let mut ch = self.dial(peer)?;
        ch.send(msg)?;
        match ch.recv()? {
            Some(v) => Ok(v),
            None => Err("empty reply".into()),
        }
    }
}

fn connect(peer: &str) -> Result<TcpStream, String> {
    let addr = peer.trim().to_string();
    let stream = TcpStream::connect(&addr).map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    Ok(stream)
}

/// Sign and gossip a precommit for a block this node accepts as valid.
pub fn vote_on(node: &Arc<Node>, p2p: &Arc<P2p>, block: &Block) {
    if !node.is_bonded_validator() || node.halted() {
        return;
    }
    let mut vote = Vote {
        height: block.height,
        hash: block.hash.clone(),
        voter_pubkey: node.producer.pubkey_hex(),
        signature: String::new(),
    };
    vote.signature = node.producer.sign_hex(&vote.signing_bytes());
    if let Ok(outcome) = node.votes.add(&node.store, vote.clone()) {
        if let Some(h) = outcome.finalized {
            println!("[final] height {} finalized", h);
        }
    }
    p2p.broadcast(&json!({ "t": "vote", "vote": vote }));
}

pub fn announce_block(p2p: &Arc<P2p>, block: &Block) {
    p2p.broadcast(&json!({ "t": "block", "block": block }));
}

pub fn announce_tx(p2p: &Arc<P2p>, tx: &Transaction) {
    p2p.broadcast(&json!({ "t": "tx", "tx": tx }));
}

/// Gossip a proof of equivocation and try to get it on chain. Reporting is
/// permissionless and pays a bounty, so honest nodes race to submit it.
pub fn announce_evidence(node: &Arc<Node>, p2p: &Arc<P2p>, evidence: &Evidence) {
    if let Err(e) = node.submit_report(evidence) {
        eprintln!("[slash] report not submitted: {}", e);
    }
    p2p.broadcast(&json!({ "t": "evidence", "evidence": evidence }));
}

/// Drain any equivocation proofs the vote tracker collected and report them.
pub fn flush_vote_evidence(node: &Arc<Node>, p2p: &Arc<P2p>) {
    for evidence in node.votes.take_evidence() {
        announce_evidence(node, p2p, &evidence);
    }
}

/// Accept inbound peer connections.
pub fn serve(node: Arc<Node>, p2p: Arc<P2p>) -> Result<(), String> {
    let listener = TcpListener::bind(&p2p.listen).map_err(|e| e.to_string())?;
    println!(
        "[p2p] listening on {} ({} peers, encryption {})",
        p2p.listen,
        p2p.peers.len(),
        if p2p.require_encryption {
            "required"
        } else {
            "preferred"
        }
    );
    if !p2p.allowed_ids.is_empty() {
        println!(
            "[p2p] allowlist active: {} node keys",
            p2p.allowed_ids.len()
        );
    }
    let limiter = Arc::new(RateLimiter::new(P2P_MSGS_PER_SEC, P2P_BURST));
    let conns = Arc::new(ConnGuard::new(P2P_MAX_LIVE_CONNS));
    let per_ip = Arc::new(IpConnCounter::new(P2P_MAX_CONNS_PER_IP));
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let ip = s.peer_addr().ok().map(|a| a.ip());
                if let Some(ip) = ip {
                    if p2p.book.is_banned(ip) || !limiter.allow(ip) {
                        continue; // banned or shouting: drop without a reply
                    }
                }
                let n = Arc::clone(&node);
                let p = Arc::clone(&p2p);
                let cg = Arc::clone(&conns);
                let pip = Arc::clone(&per_ip);
                std::thread::spawn(move || {
                    let static_peer = ip.map(|i| p.is_static_peer(i)).unwrap_or(false);
                    // Configured validators bypass the global cap so a flood of
                    // strangers cannot eclipse the node from its real peers.
                    let _ticket = match cg.try_acquire() {
                        Some(t) => Some(t),
                        None if static_peer => None,
                        None => return,
                    };
                    let _ip_ticket = match ip {
                        Some(i) if !static_peer => match pip.try_acquire(i) {
                            Some(t) => Some(t),
                            None => return, // this host already has enough slots
                        },
                        _ => None,
                    };
                    if let Err(e) = handle_conn(n, p, s, ip) {
                        eprintln!("[p2p] connection error: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("[p2p] accept error: {}", e),
        }
    }
    Ok(())
}

/// Sniff the first bytes: INSC1 means an encrypted peer, anything else is a
/// legacy plaintext JSON line (refused when encryption is required).
fn accept_channel(mut stream: TcpStream, p2p: &Arc<P2p>) -> Result<Channel, String> {
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut head = [0u8; 5];
    let mut got = 0usize;
    while got < head.len() {
        match stream.read(&mut head[got..]) {
            Ok(0) => return Err("peer closed during handshake".into()),
            Ok(n) => got += n,
            Err(e) => return Err(e.to_string()),
        }
    }
    if &head == MAGIC {
        let mut ei = [0u8; 32];
        stream.read_exact(&mut ei).map_err(|e| e.to_string())?;
        let ch = transport::handshake_responder(stream, &p2p.id, ei)?;
        if !p2p.id_allowed(ch.peer_id()) {
            return Err(format!(
                "rejected peer {:?}: not on allowlist",
                ch.peer_id()
            ));
        }
        return Ok(ch);
    }
    if p2p.require_encryption {
        return Err("refused plaintext peer (encryption required)".into());
    }
    if !p2p.allowed_ids.is_empty() {
        return Err("refused plaintext peer (allowlist requires authentication)".into());
    }
    transport::plain_channel(stream, head.to_vec())
}

fn handle_conn(
    node: Arc<Node>,
    p2p: Arc<P2p>,
    stream: TcpStream,
    ip: Option<IpAddr>,
) -> Result<(), String> {
    let read_stream = stream.try_clone().map_err(|e| e.to_string())?;
    let mut ch = match accept_channel(stream, &p2p) {
        Ok(c) => c,
        Err(e) => {
            if let Some(ip) = ip {
                p2p.book.penalize(ip, COST_BAD_MESSAGE);
            }
            return Err(e);
        }
    };
    // Sessions are long-lived; a peer may legitimately be quiet between blocks.
    read_stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .ok();
    if let (Some(ip), false) = (ip, ch.is_encrypted()) {
        p2p.book.penalize(ip, COST_PLAINTEXT);
    }
    if let (Some(id), Some(ip)) = (ch.peer_id(), ip) {
        // Sessions are short-lived per gossip message, so only announce a peer
        // identity the first time it is seen.
        if p2p.book.note_identity(ip, id) {
            println!(
                "[p2p] authenticated peer {} ({}…)",
                ip,
                &id[..8.min(id.len())]
            );
        }
    }
    loop {
        match ch.recv() {
            Ok(None) => break,
            Ok(Some(Value::Null)) => continue,
            Ok(Some(msg)) => {
                if let Some(reply) = handle_msg(&node, &p2p, &msg, ip) {
                    if ch.send(&reply).is_err() {
                        break;
                    }
                }
                if let Some(ip) = ip {
                    p2p.book.reward(ip);
                }
            }
            Err(e) => {
                // Garbage on an authenticated channel cannot be an accident.
                if let Some(ip) = ip {
                    p2p.book.penalize(ip, COST_BAD_MESSAGE);
                }
                return Err(e);
            }
        }
    }
    Ok(())
}

fn handle_msg(node: &Arc<Node>, p2p: &Arc<P2p>, msg: &Value, ip: Option<IpAddr>) -> Option<Value> {
    match msg.get("t").and_then(|t| t.as_str()).unwrap_or("") {
        "status" => Some(json!({
            "t": "statusres",
            "height": node.store.tip_height().unwrap_or(0),
            "hash": node.store.tip_hash(),
            "finalized": node.store.finalized_height(),
            // Lowest block body this node can still serve. Peers need it to
            // tell "you are behind" apart from "I pruned the history you want",
            // which is unrecoverable by block sync and needs a snapshot.
            "earliest": node.store.pruned_below(),
        })),
        "getblocks" => {
            let from = msg.get("from").and_then(|v| v.as_u64()).unwrap_or(0);
            let limit = msg
                .get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(MAX_SYNC_BATCH)
                .min(MAX_SYNC_BATCH);
            let tip = node.store.tip_height().unwrap_or(0);
            let mut blocks = Vec::new();
            let mut h = from;
            while h <= tip && (blocks.len() as u64) < limit {
                if let Some(b) = node.store.block(h) {
                    blocks.push(b);
                }
                h += 1;
            }
            Some(json!({ "t": "blocks", "blocks": blocks }))
        }
        "tx" => {
            let tx: Transaction = serde_json::from_value(msg.get("tx").cloned()?).ok()?;
            if node.accept_tx(tx).is_ok() {
                // Accepted locally; peers we know already have it from the sender.
            }
            None
        }
        "vote" => {
            let vote: Vote = serde_json::from_value(msg.get("vote").cloned()?).ok()?;
            match node.votes.add(&node.store, vote.clone()) {
                Ok(outcome) => {
                    if let Some(h) = outcome.finalized {
                        println!("[final] height {} finalized", h);
                    }
                    if outcome.fresh {
                        p2p.broadcast(&json!({ "t": "vote", "vote": vote }));
                    }
                }
                Err(e) => {
                    if e.starts_with("equivocating vote") {
                        flush_vote_evidence(node, p2p);
                    }
                }
            }
            None
        }
        "evidence" => {
            let evidence: Evidence = serde_json::from_value(msg.get("evidence").cloned()?).ok()?;
            if evidence.verify().is_ok() && node.submit_report(&evidence).is_ok() {
                p2p.broadcast(&json!({ "t": "evidence", "evidence": evidence }));
            }
            None
        }
        "block" => {
            let block: Block = serde_json::from_value(msg.get("block").cloned()?).ok()?;
            // Before anything else: a conflicting block at a height we already
            // have is provable equivocation by its producer.
            if let Some(evidence) = node.detect_double_sign(&block) {
                announce_evidence(node, p2p, &evidence);
            }
            match node.import_block(&block) {
                Ok(true) => {
                    println!(
                        "[sync] imported #{} from peer ({} txs)",
                        block.height,
                        block.transactions.len()
                    );
                    vote_on(node, p2p, &block);
                    p2p.broadcast(&json!({ "t": "block", "block": block }));
                }
                Ok(false) => {}
                Err(e) => {
                    // Likely a gap: pull the missing range from peers instead.
                    if block.height > node.store.tip_height().unwrap_or(0) + 1 {
                        let n = Arc::clone(node);
                        let p = Arc::clone(p2p);
                        std::thread::spawn(move || sync_once(&n, &p));
                    } else {
                        eprintln!("[p2p] rejected block #{}: {}", block.height, e);
                        // An invalid block at a height we can judge is misbehaviour.
                        if let Some(ip) = ip {
                            p2p.book.penalize(ip, COST_BAD_BLOCK);
                        }
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Pull any blocks this node is missing from every peer, in order.
pub fn sync_once(node: &Arc<Node>, p2p: &Arc<P2p>) {
    // Skip rather than queue: another thread is already pulling the same range.
    let _gate = match SYNC_GATE.try_lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    for peer in &p2p.peers {
        let status = p2p.request(peer, &json!({ "t": "status" })).ok();
        let peer_height = status
            .as_ref()
            .and_then(|s| s.get("height"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        // Let block production know how far ahead the network is, so a lagging
        // validator waits instead of forking off its own stale tip.
        crate::types::note_peer_height(peer_height);
        let from = node.store.tip_height().unwrap_or(0) + 1;
        if peer_height + 1 < from {
            continue; // peer is behind us; nothing to pull
        }
        // A pruned peer cannot serve the blocks between our tip and its floor.
        // Retrying forever ("out of order") is the failure mode that leaves a
        // fresh or reset node stuck at height 0 indefinitely, so say plainly
        // what the operator has to do and move on to the next peer.
        let peer_earliest = status
            .as_ref()
            .and_then(|s| s.get("earliest"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if peer_earliest > from {
            eprintln!(
                "[sync] {} pruned history below #{} and we are at #{}: block sync cannot bridge \
                 that gap. Restore a snapshot (inazuma snapshot-import) to jump to a recent state.",
                peer,
                peer_earliest,
                from - 1
            );
            continue;
        }
        let res = match p2p.request(
            peer,
            &json!({ "t": "getblocks", "from": from, "limit": MAX_SYNC_BATCH }),
        ) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let blocks: Vec<Block> = match res.get("blocks").cloned() {
            Some(v) => serde_json::from_value(v).unwrap_or_default(),
            None => continue,
        };
        for b in blocks {
            match node.import_block(&b) {
                Ok(true) => {
                    println!("[sync] block #{} from {}", b.height, peer);
                    vote_on(node, p2p, &b);
                }
                Ok(false) => {}
                Err(e) => {
                    eprintln!("[sync] stopped at #{}: {}", b.height, e);
                    // A parent mismatch means the two nodes forked. The longer
                    // chain wins; at equal length the lower block hash wins, so
                    // both sides pick the same branch without negotiating.
                    if e.contains("parent hash mismatch")
                        && should_adopt(node, &b, peer_height)
                        && now_secs().saturating_sub(LAST_RESET.load(Ordering::Relaxed))
                            > RESET_COOLDOWN_SECS
                    {
                        resolve_fork(node, p2p, peer, peer_height);
                    }
                    break;
                }
            }
        }
    }
}

/// Deterministic fork choice: longest chain, then lowest hash at the first
/// divergent height. Every honest node reaches the same verdict.
fn should_adopt(node: &Arc<Node>, peer_block: &Block, peer_height: u64) -> bool {
    let ours = node.store.tip_height().unwrap_or(0);
    if peer_height > ours {
        return true;
    }
    if peer_height < ours {
        return false;
    }
    match node.store.block(peer_block.height) {
        Some(local) => peer_block.hash < local.hash,
        None => true,
    }
}

/// Adopt a peer's longer chain by rebuilding local state from genesis.
fn resolve_fork(node: &Arc<Node>, p2p: &Arc<P2p>, peer: &str, peer_height: u64) {
    // Never destroy local state on a peer's word. The claim has to be backed by
    // a signed header at the claimed tip, and the peer's chain has to contain
    // the history this node already finalized. A lying or eclipsing peer can
    // otherwise force honest nodes to wipe their database on demand.
    if let Err(e) = verify_peer_claim(node, p2p, peer, peer_height) {
        eprintln!("[fork] refusing to follow {}: {}", peer, e);
        if let Some(ip) = peer.split(':').next().and_then(|h| h.parse().ok()) {
            p2p.book.penalize(ip, COST_BAD_BLOCK);
        }
        return;
    }
    // Replaying from genesis only works if the peer still has the history. On a
    // pruned network it does not: the node wipes a good database, cannot refill
    // it, and sits at height 0 forever. Keep local state instead and let the
    // operator restore a snapshot.
    let peer_earliest = p2p
        .request(peer, &json!({ "t": "status" }))
        .ok()
        .and_then(|s| s.get("earliest").and_then(|v| v.as_u64()))
        .unwrap_or(0);
    if peer_earliest > 1 {
        eprintln!(
            "[fork] not replaying from genesis: {} pruned below #{}. Keeping local state at #{} — \
             restore a snapshot if this node is on a dead branch.",
            peer,
            peer_earliest,
            node.store.tip_height().unwrap_or(0)
        );
        return;
    }
    println!(
        "[fork] peer {} has the longer chain (#{} vs #{}), replaying from genesis",
        peer,
        peer_height,
        node.store.tip_height().unwrap_or(0)
    );
    LAST_RESET.store(now_secs(), Ordering::Relaxed);
    if let Err(e) = node.reset_to_genesis(peer_height) {
        eprintln!("[fork] {}", e);
        return;
    }
    let mut next = 1u64;
    // The peer keeps producing while we replay, so follow its live tip instead
    // of the height it reported when the fork was detected.
    let mut target = peer_height;
    while next <= target {
        let res = match p2p.request(
            peer,
            &json!({ "t": "getblocks", "from": next, "limit": MAX_SYNC_BATCH }),
        ) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[fork] fetch failed: {}", e);
                return;
            }
        };
        let blocks: Vec<Block> = match res.get("blocks").cloned() {
            Some(v) => serde_json::from_value(v).unwrap_or_default(),
            None => Vec::new(),
        };
        if blocks.is_empty() {
            // Ask the peer where it is now; if it has advanced, keep going.
            let live = p2p
                .request(peer, &json!({ "t": "status" }))
                .ok()
                .and_then(|s| s.get("height").and_then(|v| v.as_u64()))
                .unwrap_or(target);
            if live > target {
                target = live;
                continue;
            }
            break;
        }
        let before = next;
        for b in &blocks {
            match node.import_block(b) {
                Ok(_) => next = b.height + 1,
                Err(e) => {
                    eprintln!("[fork] replay stopped at #{}: {}", b.height, e);
                    // Keep every block already replayed. Normal in-order sync
                    // resumes from the new tip on the next round instead of
                    // discarding hundreds of thousands of blocks again.
                    println!(
                        "[fork] keeping progress at #{}",
                        node.store.tip_height().unwrap_or(0)
                    );
                    return;
                }
            }
        }
        if next == before {
            break; // peer served only blocks we already have
        }
    }
    println!(
        "[fork] resolved, now at #{}",
        node.store.tip_height().unwrap_or(0)
    );
    if let Some(b) = node.store.tip_height().and_then(|h| node.store.block(h)) {
        vote_on(node, p2p, &b);
    }
}

/// Fetch one block from a peer at an exact height.
fn peer_block(p2p: &Arc<P2p>, peer: &str, height: u64) -> Option<Block> {
    let res = p2p
        .request(
            peer,
            &json!({ "t": "getblocks", "from": height, "limit": 1 }),
        )
        .ok()?;
    let blocks: Vec<Block> = serde_json::from_value(res.get("blocks").cloned()?).ok()?;
    blocks.into_iter().find(|b| b.height == height)
}

/// Authenticate a fork claim before any local state is discarded.
fn verify_peer_claim(
    node: &Arc<Node>,
    p2p: &Arc<P2p>,
    peer: &str,
    peer_height: u64,
) -> Result<(), String> {
    let tip = peer_block(p2p, peer, peer_height).ok_or("peer cannot serve its own claimed tip")?;
    if tip.height != peer_height {
        return Err("peer served the wrong height".into());
    }
    if tip.hash != tip.compute_hash() {
        return Err("peer tip hash does not match its header".into());
    }
    if !tip.verify_producer() {
        return Err("peer tip carries no valid producer signature".into());
    }
    // The fork must build on the history we already consider irreversible.
    // The finalized marker survives a reset-to-genesis as a safety floor, so it
    // can sit above the local tip while a replay is still in progress. Compare
    // at the highest height we can actually back with a local block, otherwise
    // an interrupted replay leaves the node permanently unable to follow anyone.
    let mut check = node
        .store
        .finalized_height()
        .min(node.store.tip_height().unwrap_or(0));
    while check > 0 && node.store.block(check).is_none() {
        check -= 1;
    }
    if check > 0 {
        let ours = node
            .store
            .block(check)
            .ok_or("local finalized block missing")?;
        let theirs =
            peer_block(p2p, peer, check).ok_or("peer cannot serve our finalized height")?;
        if theirs.hash != ours.hash {
            return Err(format!(
                "peer chain diverges below finalized height {} (ours {} theirs {})",
                check,
                &ours.hash[..8.min(ours.hash.len())],
                &theirs.hash[..8.min(theirs.hash.len())]
            ));
        }
    }
    Ok(())
}

/// Background catch-up loop, so a node that was offline rejoins on its own.
pub fn sync_loop(node: Arc<Node>, p2p: Arc<P2p>) {
    loop {
        sync_once(&node, &p2p);
        std::thread::sleep(Duration::from_millis(2_000));
    }
}
