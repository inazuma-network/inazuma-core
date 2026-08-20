//! Inazuma node — a blockchain written from scratch. INAZ is the native coin.
//!
//! Commands:
//!   inazuma keygen
//!   inazuma init   --data <dir> --genesis <file>
//!   inazuma run    --data <dir> --genesis <file> --key <hex> --rpc 0.0.0.0:9933
//!   inazuma send   --rpc <url> --key <hex> --to <addr> --amount <INAZ>
//!   inazuma balance --rpc <url> --address <addr>

#[cfg(test)]
mod battletest;
mod chain;
mod conformance;
mod consensus;
mod contracts;
mod crypto;
mod events;
mod fees;
mod fuzz;
mod journal;
mod limits;
mod log;
mod mempool;
mod p2p;
mod qos;
mod rpc;
mod rpcauth;
mod simulate;
mod signguard;
mod slashing;
mod smt;
mod snapshot;
mod staking;
mod state;
mod tokens;
mod transport;
mod types;
mod ui;
mod ws;

use chain::Node;
use crypto::Keypair;
use state::Store;
use std::collections::HashMap;
use std::sync::Arc;
use types::{format_inaz, parse_inaz, Genesis, Payload, Transaction, TxKind, CHAIN_ID, MIN_FEE};

/// Blocks of history a pruning node keeps behind the finalized height.
/// ~2 days at 400 ms blocks: enough for peers to catch up, small on disk.
pub const DEFAULT_PRUNE_KEEP: u64 = 400_000;

fn args() -> (String, HashMap<String, String>) {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let cmd = raw.first().cloned().unwrap_or_else(|| "help".into());
    let mut flags = HashMap::new();
    let mut i = 1;
    while i < raw.len() {
        if let Some(name) = raw[i].strip_prefix("--") {
            // A switch (--replica) has no value. Only consume the next token when
            // it is not itself a flag, otherwise a switch would swallow the flag
            // that follows it and silently drop its value.
            let next = raw.get(i + 1);
            let takes_value = next.map(|v| !v.starts_with("--")).unwrap_or(false);
            let value = if takes_value {
                next.cloned().unwrap_or_default()
            } else {
                String::new()
            };
            flags.insert(name.to_string(), value);
            i += if takes_value { 2 } else { 1 };
        } else {
            i += 1;
        }
    }
    (cmd, flags)
}

fn load_genesis(path: &str, flags: &HashMap<String, String>) -> Result<Genesis, String> {
    if let Ok(text) = std::fs::read_to_string(path) {
        return serde_json::from_str(&text).map_err(|e| format!("bad genesis: {}", e));
    }
    let admin = flags.get("admin").cloned().ok_or_else(|| {
        format!(
            "genesis file {} not found; pass --admin <inz address> to create one",
            path
        )
    })?;
    let g = Genesis::default_devnet(&admin);
    std::fs::write(path, serde_json::to_string_pretty(&g).unwrap()).map_err(|e| e.to_string())?;
    println!(
        "[genesis] created {} with 1,000,000 INAZ to {}",
        path, admin
    );
    Ok(g)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let (cmd, flags) = args();
    let data = flags
        .get("data")
        .cloned()
        .unwrap_or_else(|| "./data".into());
    let genesis_path = flags
        .get("genesis")
        .cloned()
        .unwrap_or_else(|| "./genesis.json".into());

    match cmd.as_str() {
        "keygen" => {
            let kp = Keypair::generate();
            println!("address:    {}", kp.address());
            println!("public key: {}", kp.pubkey_hex());
            println!("secret key: {}", kp.secret_hex());
            println!("\nKeep the secret key safe. It controls this account.");
            Ok(())
        }

        "address" => {
            let kp = Keypair::from_secret_hex(flags.get("key").ok_or("--key required")?)?;
            println!("{}", kp.address());
            Ok(())
        }

        "init" => {
            let genesis = load_genesis(&genesis_path, &flags)?;
            let store = Store::open(&data)?;
            let producer = producer_key(&flags, &data)?;
            let node = Node::new(store, genesis, producer);
            let block = node.init_genesis()?;
            println!("[init] genesis sealed");
            println!("  height 0 hash {}", block.hash);
            println!("  state root    {}", block.state_root);
            println!(
                "  supply        {} INAZ",
                format_inaz(node.store.total_supply())
            );
            Ok(())
        }

        // ---- operator tooling: snapshots, pruning, emergency halt ----
        "snapshot-export" => {
            let out = flags
                .get("out")
                .cloned()
                .unwrap_or_else(|| "./snapshot.json".into());
            let genesis = load_genesis(&genesis_path, &flags)?;
            let store = Store::open(&data)?;
            let snap = snapshot::export(&store, genesis.chain_id)?;
            std::fs::write(&out, serde_json::to_vec(&snap).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            println!("[snapshot] height {} root {}", snap.height, snap.state_root);
            println!("[snapshot] block hash {}", snap.block_hash);
            println!("[snapshot] {} state entries -> {}", snap.entry_count(), out);
            println!(
                "\nVerify the block hash against a second node or the explorer before importing."
            );
            Ok(())
        }

        "snapshot-import" => {
            let file = flags
                .get("in")
                .cloned()
                .ok_or("--in <snapshot.json> required")?;
            let genesis = load_genesis(&genesis_path, &flags)?;
            let raw = std::fs::read(&file).map_err(|e| e.to_string())?;
            let snap: snapshot::Snapshot =
                serde_json::from_slice(&raw).map_err(|e| format!("bad snapshot: {}", e))?;
            let store = Store::open(&data)?;
            let height = snapshot::import(&store, &snap, genesis.chain_id)?;
            println!("[snapshot] verified and imported at height {}", height);
            println!("[snapshot] state root {}", store.state_root_at(height));
            println!("[snapshot] sync will continue from height {}", height + 1);
            Ok(())
        }

        "prune" => {
            let keep = flags
                .get("keep")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(DEFAULT_PRUNE_KEEP);
            let store = Store::open(&data)?;
            let finalized = store.finalized_height();
            let removed = store.prune_blocks(finalized.saturating_sub(keep));
            println!(
                "[prune] removed {} block bodies below {}",
                removed,
                store.pruned_below()
            );
            println!("[prune] finalized {} keep {} blocks", finalized, keep);
            Ok(())
        }

        "halt" => {
            let store = Store::open(&data)?;
            let reason = flags
                .get("reason")
                .cloned()
                .unwrap_or_else(|| "operator halt".into());
            store.set_halt(&reason);
            println!(
                "[halt] node will stop producing, voting and importing: {}",
                reason
            );
            println!("[halt] restart is not enough to clear this; run `inazuma resume`.");
            Ok(())
        }

        "resume" => {
            let store = Store::open(&data)?;
            store.clear_halt();
            println!("[halt] cleared; restart the node to resume consensus");
            Ok(())
        }

        "run" => {
            let genesis = load_genesis(&genesis_path, &flags)?;
            let block_time = flags
                .get("block-time")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(genesis.block_time_ms);
            let rpc_addr = flags
                .get("rpc")
                .cloned()
                .unwrap_or_else(|| "0.0.0.0:9933".into());
            // Live-subscription endpoint. Empty string disables it.
            let ws_addr = flags
                .get("ws")
                .cloned()
                .or_else(|| std::env::var("INAZ_WS_ADDR").ok())
                .unwrap_or_else(|| "0.0.0.0:9955".into());
            // Read replica: sync and serve, never produce or vote.
            let replica = flags.contains_key("replica") || std::env::var("INAZ_REPLICA").is_ok();
            let p2p_addr = flags
                .get("p2p")
                .cloned()
                .unwrap_or_else(|| "0.0.0.0:9944".into());
            let peers: Vec<String> = flags
                .get("peers")
                .map(|s| {
                    s.split(',')
                        .map(|p| p.trim().to_string())
                        .filter(|p| !p.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            let store = Store::open(&data)?;
            let producer = producer_key(&flags, &data)?;
            // The P2P handshake authenticates with the same ed25519 node key, so
            // peers can pin exactly which validators they will talk to.
            let node_id = Arc::new(crypto::Keypair::from_secret_hex(&producer.secret_hex())?);
            let allowed_ids: std::collections::HashSet<String> = flags
                .get("peer-ids")
                .map(|s| {
                    s.split(',')
                        .map(|k| k.trim().to_lowercase())
                        .filter(|k| k.len() == 64)
                        .collect()
                })
                .unwrap_or_default();
            let require_encryption = flags.contains_key("require-encrypted-p2p")
                || std::env::var("INAZ_REQUIRE_ENCRYPTED_P2P").is_ok();
            let node = Arc::new(Node::new(store, genesis, producer));
            let network = Arc::new(
                p2p::P2p::new(p2p_addr, peers, Arc::clone(&node_id))
                    .with_allowlist(allowed_ids)
                    .with_required_encryption(require_encryption),
            );
            node.attach_gossip(Arc::clone(&network));
            // Equivocation guard lives next to the data dir, not inside it, so
            // restoring a snapshot cannot forget what this key already signed.
            if !replica {
                let guard = Arc::new(signguard::SignGuard::open(&data, &node.producer.address()));
                if guard.highest_signed() > 0 {
                    println!(
                        "[guard] highest height already signed by this key: #{}",
                        guard.highest_signed()
                    );
                }
                node.attach_sign_guard(guard);
            }
            // With peers present the node follows the elected leader instead of
            // sealing every slot itself.
            node.set_serving_only(replica);
            // A replica must never seal a block, so solo mode is off regardless of
            // whether it has peers yet.
            node.set_solo(!replica && network.peers.is_empty());

            if !node.store.is_initialized() {
                let b = node.init_genesis()?;
                println!("[init] genesis sealed at height 0 ({})", b.hash);
            }

            // Integrity alarm before this node touches the network: if the state
            // on disk no longer hashes to the checkpoint written when the last
            // block finished, the database changed underneath the chain. Halt
            // loudly instead of producing or voting on state no peer can
            // reproduce.
            if let Err(why) = node.startup_state_root_check() {
                eprintln!("[ALARM] {}", why);
                eprintln!("[ALARM] refusing to start. Recover with:");
                eprintln!(
                    "        inazuma snapshot-import --data {} --file <snapshot>",
                    data
                );
                eprintln!("        (or wipe the data directory and re-sync from genesis)");
                node.store.set_halt("state divergence detected at startup");
                return Err("state divergence".into());
            }

            // Merkleized state: built once per database from current state, so an
            // upgrading validator does not have to resync from genesis.
            if !node.store.merkle_ready() {
                println!("[state] building Merkle state tree, one time only...");
                let t = std::time::Instant::now();
                node.store.build_merkle_state();
                println!(
                    "[state] Merkle root {} in {:?}",
                    &node.store.merkle_root()[..16],
                    t.elapsed()
                );
            }

            let me = node.producer.address();
            let my_stake = node.store.account(&me).staked;
            // Everything below reads the LOCAL database. On a fresh data dir that
            // is still at genesis, so stake/validator counts are zeros until the
            // node has replayed the chain. Say so instead of printing a stale 0
            // as if it were the network truth.
            let local_height = node.store.tip_height().unwrap_or(0);
            let net_height = types::best_peer_height();
            let behind = net_height > local_height + 2;
            let pending = if behind {
                format!(" — local view at #{}, syncing to #{}", local_height, net_height)
            } else {
                String::new()
            };
            // Output style. Default is the Ethereum-client log format every
            // operator already knows (geth/lighthouse style); the animated
            // Inazuma HUD stays available with `--ui hud`.
            let hud = flags
                .get("ui")
                .map(|v| v == "hud")
                .unwrap_or_else(|| std::env::var("INAZ_UI").ok().as_deref() == Some("hud"));
            if !hud {
                log::welcome(env!("CARGO_PKG_VERSION"), node.genesis.chain_id, &data, &me);
                log::info(
                    "Initialised chain configuration",
                    &[
                        ("chain", format!("inazuma-{}", node.genesis.chain_id)),
                        ("blocktime", format!("{}ms", block_time)),
                        (
                            "engine",
                            format!("pos (min stake {} INAZ)", format_inaz(types::MIN_STAKE)),
                        ),
                    ],
                );
                log::info(
                    "Loaded local state database",
                    &[
                        ("height", log::num(local_height)),
                        ("finalized", log::num(node.store.finalized_height())),
                        ("root", log::short(&node.store.merkle_root())),
                    ],
                );
                log::info(
                    "Started P2P networking",
                    &[
                        ("self", log::short(&node_id.pubkey_hex())),
                        ("peers", network.peers.len().to_string()),
                        (
                            "transport",
                            format!(
                                "INSC1-{}",
                                if network.require_encryption { "required" } else { "preferred" }
                            ),
                        ),
                    ],
                );
                log::info(
                    "HTTP server started",
                    &[("endpoint", format!("http://{}", rpc_addr))],
                );
                if !ws_addr.is_empty() {
                    log::info(
                        "WebSocket server started",
                        &[("endpoint", format!("ws://{}", ws_addr))],
                    );
                }
                log::info(
                    "Validator account ready",
                    &[
                        ("address", me.clone()),
                        ("stake", format!("{} INAZ", format_inaz(my_stake))),
                        (
                            "state",
                            if my_stake >= types::MIN_STAKE {
                                "bonded".to_string()
                            } else {
                                format!("unbonded (stake {} INAZ to validate)", format_inaz(types::MIN_STAKE))
                            },
                        ),
                    ],
                );
                if behind {
                    log::info(
                        "Starting chain synchronisation",
                        &[
                            ("from", log::num(local_height)),
                            ("target", log::num(net_height)),
                        ],
                    );
                }
                log::info(
                    "Validator dashboard",
                    &[("url", format!("{}?node={}", ui::DASHBOARD, me))],
                );
            }
            if hud {
            ui::banner();
            ui::panel(
                "node",
                &[
                    ("chain id".into(), format!("{} (Inazuma)", node.genesis.chain_id)),
                    ("validator".into(), me.clone()),
                    ("node key".into(), node_id.pubkey_hex()),
                    (
                        "p2p".into(),
                        format!(
                            "INSC1 encrypted ({}), allowlist {}",
                            if network.require_encryption { "required" } else { "preferred" },
                            if network.allowed_ids.is_empty() {
                                "off".to_string()
                            } else {
                                format!("{} keys", network.allowed_ids.len())
                            }
                        ),
                    ),
                    ("block time".into(), format!("{} ms", block_time)),
                    (
                        "mode".into(),
                        if replica {
                            "replica (serving only)".into()
                        } else if node.solo() {
                            "solo (no peers yet)".to_string()
                        } else {
                            "networked".to_string()
                        },
                    ),
                    (
                        "your stake".into(),
                        format!(
                            "{} INAZ (min {} to validate){}",
                            format_inaz(my_stake),
                            format_inaz(types::MIN_STAKE),
                            pending
                        ),
                    ),
                    (
                        "network".into(),
                        format!(
                            "{} INAZ staked across {} validators{}",
                            format_inaz(node.store.total_staked()),
                            node.validators().len(),
                            pending
                        ),
                    ),
                    ("supply".into(), format!("{} INAZ", format_inaz(node.store.total_supply()))),
                    ("rpc".into(), format!("http://{}", rpc_addr)),
                    (
                        "ws".into(),
                        if ws_addr.is_empty() {
                            "disabled".to_string()
                        } else {
                            format!("ws://{}", ws_addr)
                        },
                    ),
                    (
                        "state root".into(),
                        format!("merkle from height {}", state::STATE_ROOT_V2_ACTIVATION_HEIGHT),
                    ),
                ],
            );
            ui::dashboard_link(&me);
            ui::next_steps(&me, my_stake >= types::MIN_STAKE);
            ui::commands(my_stake >= types::MIN_STAKE);
            }

            let rpc_node = Arc::clone(&node);
            // RPC access control: keys from flags or env, comma separated.
            let key_list = |name: &str, env: &str| -> Vec<String> {
                flags
                    .get(name)
                    .cloned()
                    .or_else(|| std::env::var(env).ok())
                    .map(|s| {
                        s.split(',')
                            .map(|k| k.trim().to_string())
                            .filter(|k| !k.is_empty())
                            .collect()
                    })
                    .unwrap_or_default()
            };
            // Stake-weighted service tiers: `key:address` pairs bind an API key to a
            // bonded account, and its share of stake becomes its share of capacity.
            let stake_qos = qos::StakeQos::new(key_list("rpc-stake-keys", "INAZ_RPC_STAKE_KEYS"));
            if !stake_qos.is_empty() {
                println!(
                    "qos          {} keys weighted by stake (cap {}x)",
                    stake_qos.len(),
                    qos::MAX_STAKE_MULTIPLIER
                );
            }
            let rpc_cfg = Arc::new(rpcauth::RpcConfig::with_qos(
                key_list("rpc-keys", "INAZ_RPC_KEYS"),
                key_list("rpc-admin-keys", "INAZ_RPC_ADMIN_KEYS"),
                flags.contains_key("rpc-require-auth")
                    || std::env::var("INAZ_RPC_REQUIRE_AUTH").is_ok(),
                flags.contains_key("rpc-trust-proxy")
                    || std::env::var("INAZ_RPC_TRUST_PROXY").is_ok(),
                stake_qos,
            ));
            let http_cfg = Arc::clone(&rpc_cfg);
            std::thread::spawn(move || {
                if let Err(e) = rpc::serve_with(rpc_node, &rpc_addr, http_cfg) {
                    eprintln!("[rpc] fatal: {}", e);
                }
            });

            if !ws_addr.is_empty() {
                let ws_node = Arc::clone(&node);
                let ws_cfg = Arc::clone(&rpc_cfg);
                let ws_bind = ws_addr.clone();
                std::thread::spawn(move || {
                    if let Err(e) = ws::serve(ws_node, &ws_bind, ws_cfg) {
                        eprintln!("[ws] fatal: {}", e);
                    }
                });
            }

            let p2p_node = Arc::clone(&node);
            let p2p_net = Arc::clone(&network);
            std::thread::spawn(move || {
                if let Err(e) = p2p::serve(p2p_node, p2p_net) {
                    eprintln!("[p2p] fatal: {}", e);
                }
            });

            if !network.peers.is_empty() {
                let sync_node = Arc::clone(&node);
                let sync_net = Arc::clone(&network);
                std::thread::spawn(move || p2p::sync_loop(sync_node, sync_net));
            }

            // Optional pruning: keeps disk bounded on a validator that does not
            // need to serve deep history. Only finalized blocks are ever removed.
            if let Some(keep) = flags
                .get("prune")
                .map(|v| v.parse::<u64>().unwrap_or(DEFAULT_PRUNE_KEEP))
            {
                println!("prune        keeping {} blocks behind finality", keep);
                let prune_node = Arc::clone(&node);
                std::thread::spawn(move || loop {
                    std::thread::sleep(std::time::Duration::from_secs(600));
                    let finalized = prune_node.store.finalized_height();
                    let removed = prune_node
                        .store
                        .prune_blocks(finalized.saturating_sub(keep));
                    if removed > 0 {
                        println!(
                            "[prune] removed {} blocks, history starts at {}",
                            removed,
                            prune_node.store.pruned_below()
                        );
                    }
                });
            }

            if let Some(reason) = node.store.halt_reason() {
                println!(
                    "HALTED       {} — serving reads only, run `inazuma resume` to clear",
                    reason
                );
            }

            // Rejoin the active set on our own once a downtime jail expires.
            {
                let unjail_node = Arc::clone(&node);
                std::thread::spawn(move || loop {
                    std::thread::sleep(std::time::Duration::from_secs(30));
                    unjail_node.try_self_unjail();
                });
            }

            let mut tick = 0usize;
            let mut last_beat = std::time::Instant::now();
            // Empty blocks are logged sparsely: 400ms slots would otherwise bury
            // real events, exactly like geth does not log every idle sealing.
            let mut last_empty_log = std::time::Instant::now()
                - std::time::Duration::from_secs(30);
            let mut synced_summary_shown = false;
            loop {
                let started = std::time::Instant::now();
                match node.produce_block() {
                    Ok(Some(b)) => {
                        let empty = b.transactions.is_empty();
                        let show_empty = last_empty_log.elapsed()
                            >= std::time::Duration::from_secs(10);
                        if !hud && (!empty || show_empty) {
                            if empty {
                                last_empty_log = std::time::Instant::now();
                            }
                            log::info(
                                if empty { "Sealed new block" } else { "Imported new chain segment" },
                                &[
                                    ("number", log::num(b.height)),
                                    ("hash", log::short(&b.hash)),
                                    ("txs", b.transactions.len().to_string()),
                                    ("peers", network.peers.len().to_string()),
                                    ("elapsed", format!("{}ms", started.elapsed().as_millis())),
                                ],
                            );
                        } else if !b.transactions.is_empty() {
                            println!(
                                "\r\x1b[2K[block] #{} txs={} hash={}",
                                b.height,
                                b.transactions.len(),
                                &b.hash[..16]
                            );
                        }
                        p2p::announce_block(&network, &b);
                        p2p::vote_on(&node, &network, &b);
                    }
                    Ok(None) => { /* another validator's slot */ }
                    Err(e) => {
                        if hud {
                            eprintln!("\r\x1b[2K[block] error: {}", e);
                        } else {
                            log::error("Block production failed", &[("err", e.to_string())]);
                        }
                    }
                }
                // Live one-line status so an operator can tell at a glance whether
                // the node is syncing, validating or jailed.
                let beat_every = if hud { 1500 } else { 8000 };
                if last_beat.elapsed() >= std::time::Duration::from_millis(beat_every) {
                    last_beat = std::time::Instant::now();
                    tick += 1;
                    let height = node.store.tip_height().unwrap_or(0);
                    let v = node.validators().into_iter().find(|v| v.address == me);
                    let acct = node.store.account(&me);
                    let beat = ui::Beat {
                        height,
                        target: types::best_peer_height(),
                        peers: network.peers.len(),
                        finalized: node.store.finalized_height(),
                        staked: acct.staked,
                        validating: v.as_ref().map(|v| v.jailed_until == 0).unwrap_or(false),
                        jailed: v.as_ref().map(|v| v.jailed_until > height).unwrap_or(false),
                    };
                    if hud {
                        ui::heartbeat(tick, &beat, &format!("{} INAZ", format_inaz(acct.staked)));
                    } else if beat.peers == 0 && !node.solo() {
                        log::warn("Looking for peers", &[("peercount", "0".to_string())]);
                    } else if beat.target > height + 2 {
                        log::info(
                            "Syncing chain segment",
                            &[
                                ("number", log::num(height)),
                                ("target", log::num(beat.target)),
                                (
                                    "progress",
                                    format!(
                                        "{:.2}%",
                                        (height as f64 / beat.target.max(1) as f64) * 100.0
                                    ),
                                ),
                                ("peers", beat.peers.to_string()),
                            ],
                        );
                    } else {
                        log::info(
                            "Chain head updated",
                            &[
                                ("number", log::num(height)),
                                ("finalized", log::num(beat.finalized)),
                                ("peers", beat.peers.to_string()),
                                ("stake", format!("{} INAZ", format_inaz(acct.staked))),
                                (
                                    "role",
                                    if beat.jailed {
                                        "jailed".to_string()
                                    } else if beat.validating {
                                        "validator".to_string()
                                    } else {
                                        "full".to_string()
                                    },
                                ),
                            ],
                        );
                    }
                    // Once the local view has caught up, reprint the numbers that
                    // were still zero/stale at boot so the operator sees the real
                    // stake and validator set without restarting the node.
                    let caught_up = beat.target <= height + 2;
                    if caught_up && !synced_summary_shown {
                        synced_summary_shown = true;
                        if !hud {
                            log::info(
                                "Chain synchronisation finished",
                                &[
                                    ("height", log::num(height)),
                                    (
                                        "validators",
                                        node.validators().len().to_string(),
                                    ),
                                    (
                                        "netstake",
                                        format!("{} INAZ", format_inaz(node.store.total_staked())),
                                    ),
                                    (
                                        "you",
                                        if beat.validating {
                                            "producing blocks".to_string()
                                        } else if acct.staked >= types::MIN_STAKE {
                                            "joining active set".to_string()
                                        } else {
                                            "not staked".to_string()
                                        },
                                    ),
                                ],
                            );
                        } else {
                        ui::panel(
                            "synced",
                            &[
                                ("height".into(), format!("#{} (finalized #{})", height, beat.finalized)),
                                (
                                    "your stake".into(),
                                    format!(
                                        "{} INAZ (min {} to validate)",
                                        format_inaz(acct.staked),
                                        format_inaz(types::MIN_STAKE)
                                    ),
                                ),
                                (
                                    "network".into(),
                                    format!(
                                        "{} INAZ staked across {} validators",
                                        format_inaz(node.store.total_staked()),
                                        node.validators().len()
                                    ),
                                ),
                                (
                                    "status".into(),
                                    if beat.validating {
                                        "validating — producing blocks".into()
                                    } else if acct.staked >= types::MIN_STAKE {
                                        "staked, joining the active set".to_string()
                                    } else {
                                        format!(
                                            "not staked yet — run: inazuma stake --amount {}",
                                            format_inaz(types::MIN_STAKE)
                                        )
                                    },
                                ),
                            ],
                        );
                        }
                    }
                }
                let elapsed = started.elapsed().as_millis() as u64;
                if elapsed < block_time {
                    std::thread::sleep(std::time::Duration::from_millis(block_time - elapsed));
                }
            }
        }

        "balance" => {
            let rpc_url = flags
                .get("rpc")
                .cloned()
                .unwrap_or_else(|| "http://127.0.0.1:9933".into());
            let address = flags.get("address").ok_or("--address required")?.clone();
            let res = rpc_call(
                &rpc_url,
                "inaz_getAccount",
                serde_json::json!({ "address": address }),
            )?;
            println!(
                "{} => {} INAZ (staked {}, unbonding {}, rewards {}, nonce {})",
                address,
                res["balanceInaz"].as_str().unwrap_or("0"),
                res["stakedInaz"].as_str().unwrap_or("0"),
                res["unbondingInaz"].as_str().unwrap_or("0"),
                res["rewardsInaz"].as_str().unwrap_or("0"),
                res["nonce"]
            );
            Ok(())
        }

        "status" => {
            let rpc_url = flags
                .get("rpc")
                .cloned()
                .unwrap_or_else(|| "http://127.0.0.1:9933".into());
            let res = rpc_call(&rpc_url, "inaz_nodeStatus", serde_json::json!({}))?;
            let height = res["height"].as_u64().unwrap_or(0);
            let finalized = res["finalizedHeight"].as_u64().unwrap_or(0);
            let syncing = res["syncing"].as_bool().unwrap_or(false);
            println!("rpc            {}", rpc_url);
            println!("chain id       {}", res["chainId"]);
            println!("role           {}", res["role"].as_str().unwrap_or("node"));
            println!("height         {}", height);
            println!("finalized      {}", finalized);
            println!("peers          {}", res["peers"]);
            println!("mempool        {}", res["mempool"]);
            println!(
                "sync           {}",
                if syncing { "syncing — do not stake yet" } else { "in sync" }
            );
            // Comparing against the public tip means telling the foundation's RPC
            // that this operator's node exists, so it is opt-in: pass
            // `--compare` (or `--compare URL`) or set INAZ_STATUS_COMPARE=1.
            let compare = flags.contains_key("compare")
                || std::env::var("INAZ_STATUS_COMPARE").is_ok_and(|v| v != "0");
            if compare {
                let remote = flags
                    .get("compare")
                    .filter(|v| v.starts_with("http"))
                    .cloned()
                    .unwrap_or_else(|| "https://rpc.inazuma.network".into());
                if let Ok(net) = rpc_call(&remote, "inaz_nodeStatus", serde_json::json!({})) {
                    let tip = net["height"].as_u64().unwrap_or(0);
                    if tip > 0 && !rpc_url.contains(remote.trim_start_matches("https://")) {
                        println!(
                            "network tip    {} (behind by {}, via {})",
                            tip,
                            tip.saturating_sub(height),
                            remote
                        );
                    }
                }
            } else {
                println!("network tip    (skipped — pass --compare to query the public RPC)");
            }
            Ok(())
        }

        "validators" => {
            let rpc_url = flags
                .get("rpc")
                .cloned()
                .unwrap_or_else(|| "http://127.0.0.1:9933".into());
            let res = rpc_call(&rpc_url, "inaz_validators", serde_json::json!({}))?;
            println!("validators   {}", res["count"]);
            println!(
                "total stake  {} INAZ",
                res["totalStakeInaz"].as_str().unwrap_or("0")
            );
            println!(
                "min stake    {} INAZ",
                res["minStakeInaz"].as_str().unwrap_or("0")
            );
            println!(
                "next leader  {}",
                res["nextLeader"].as_str().unwrap_or("(bootstrap)")
            );
            if let Some(list) = res["validators"].as_array() {
                for v in list {
                    println!(
                        "  {}  {} INAZ  {}%  blocks {}  rewards {} INAZ",
                        v["address"].as_str().unwrap_or(""),
                        v["stakeInaz"].as_str().unwrap_or("0"),
                        v["sharePct"],
                        v["blocksProduced"],
                        v["rewardsInaz"].as_str().unwrap_or("0"),
                    );
                }
            }
            Ok(())
        }

        "finality" => {
            let rpc_url = flags
                .get("rpc")
                .cloned()
                .unwrap_or_else(|| "http://127.0.0.1:9933".into());
            let mut params = serde_json::json!({});
            if let Some(h) = flags.get("height").and_then(|h| h.parse::<u64>().ok()) {
                params = serde_json::json!({ "height": h });
            }
            let res = rpc_call(&rpc_url, "inaz_finality", params)?;
            println!("tip height        {}", res["tipHeight"]);
            println!("finalized height  {}", res["finalizedHeight"]);
            println!(
                "queried height    {} (final: {})",
                res["height"], res["isFinal"]
            );
            println!(
                "precommits        {} of {} validators",
                res["votes"], res["validators"]
            );
            println!(
                "voted stake       {} INAZ ({}% of {} INAZ, need >66.67%)",
                res["votedStakeInaz"].as_str().unwrap_or("0"),
                res["votedPct"],
                res["totalStakeInaz"].as_str().unwrap_or("0")
            );
            println!("peers             {}", res["peers"]);
            Ok(())
        }

        "slashing" => {
            let rpc_url = flags
                .get("rpc")
                .cloned()
                .unwrap_or_else(|| "http://127.0.0.1:9933".into());
            let res = rpc_call(&rpc_url, "inaz_slashing", serde_json::json!({}))?;
            println!("height              {}", res["height"]);
            println!(
                "enforcement         {} (from #{})",
                if res["active"].as_bool().unwrap_or(false) {
                    "active"
                } else {
                    "pending"
                },
                res["activationHeight"]
            );
            let p = &res["params"];
            println!(
                "equivocation burn   max({}%, {}x stake share) of stake + permanent tombstone",
                p["equivocationMinBurnPct"], p["equivocationCorrelationFactor"]
            );
            println!(
                "reporter bounty     {}% of the burn",
                p["reporterBountyPct"]
            );
            println!(
                "downtime jail       {} consecutive missed slots -> {} blocks in jail",
                p["downtimeJailStreak"], p["downtimeJailBlocks"]
            );
            println!(
                "total burned        {} INAZ across {} slashes",
                res["totalBurnedInaz"].as_str().unwrap_or("0"),
                res["slashCount"]
            );
            if let Some(list) = res["slashes"].as_array() {
                for s in list {
                    println!(
                        "  #{} {:<12} {}  burned {} INAZ  bounty {} INAZ  reporter {}",
                        s["appliedHeight"],
                        s["offence"].as_str().unwrap_or(""),
                        s["offender"].as_str().unwrap_or(""),
                        s["burnedInaz"].as_str().unwrap_or("0"),
                        s["bountyInaz"].as_str().unwrap_or("0"),
                        s["reporter"].as_str().unwrap_or("-"),
                    );
                }
            }
            Ok(())
        }

        // Submit a proof of equivocation held in a JSON file and collect the bounty.
        "report" => {
            let rpc_url = flags
                .get("rpc")
                .cloned()
                .unwrap_or_else(|| "http://127.0.0.1:9933".into());
            let path = flags
                .get("evidence")
                .ok_or("--evidence <file.json> required")?;
            let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            let evidence: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| format!("bad evidence file: {}", e))?;
            let preview = rpc_call(
                &rpc_url,
                "inaz_previewSlash",
                serde_json::json!({ "evidence": evidence }),
            )?;
            println!("offender   {}", preview["offender"].as_str().unwrap_or(""));
            println!(
                "offence    {} at #{}",
                preview["offence"].as_str().unwrap_or(""),
                preview["offenceHeight"]
            );
            println!(
                "burn       {} INAZ ({}% of stake)",
                preview["burnInaz"].as_str().unwrap_or("0"),
                preview["burnPct"]
            );
            println!(
                "bounty     {} INAZ",
                preview["bountyInaz"].as_str().unwrap_or("0")
            );
            let res = rpc_call(
                &rpc_url,
                "inaz_reportEquivocation",
                serde_json::json!({ "evidence": evidence }),
            )?;
            println!("submitted  {}", res["hash"].as_str().unwrap_or("?"));
            Ok(())
        }

        // Leave a downtime jail once the jail period is over.
        "unjail" => {
            let rpc_url = flags
                .get("rpc")
                .cloned()
                .unwrap_or_else(|| "http://127.0.0.1:9933".into());
            let kp = Keypair::from_secret_hex(flags.get("key").ok_or("--key required")?)?;
            let acct = rpc_call(
                &rpc_url,
                "inaz_getAccount",
                serde_json::json!({ "address": kp.address() }),
            )?;
            let nonce = acct["pendingNonce"]
                .as_u64()
                .or_else(|| acct["nonce"].as_u64())
                .unwrap_or(0);
            let fee = flags
                .get("fee")
                .map(|f| parse_inaz(f))
                .transpose()?
                .unwrap_or(MIN_FEE);
            let mut tx = Transaction {
                kind: TxKind::Unjail,
                from_pubkey: kp.pubkey_hex(),
                to: kp.address(),
                amount: 0,
                fee,
                nonce,
                chain_id: CHAIN_ID,
                payload: None,
                signature: String::new(),
            };
            tx.signature = kp.sign_hex(&tx.signing_bytes());
            let res = rpc_call(
                &rpc_url,
                "inaz_sendTransaction",
                serde_json::json!({ "tx": tx }),
            )?;
            println!("unjail submitted: {}", res["hash"].as_str().unwrap_or("?"));
            Ok(())
        }

        // ---- wallet: create, import, inspect. Keeps the operator out of shell
        // quoting hell by owning ~/.inazuma/validator.env itself.
        "wallet-new" | "wallet-import" | "wallet" => {
            let path = wallet_path();
            match cmd.as_str() {
                "wallet-new" => {
                    if wallet_secret().is_ok() && !flags.contains_key("force") {
                        return Err(format!(
                            "{} already holds a wallet. Pass --force to overwrite (funds are lost if you have no backup)",
                            path
                        ));
                    }
                    let kp = Keypair::generate();
                    write_wallet(&kp)?;
                    ui::banner();
                    ui::panel(
                        "new wallet",
                        &[
                            ("address".into(), kp.address()),
                            ("saved to".into(), path.clone()),
                            ("backup".into(), "print the secret with: inazuma wallet --reveal".into()),
                        ],
                    );
                    println!("\nFund it, then run `inazuma stake --amount 1000`.");
                    println!("Faucet: https://inazuma.network/faucet");
                    Ok(())
                }
                "wallet-import" => {
                    let kp = Keypair::from_secret_hex(
                        flags.get("key").ok_or("--key <64 hex chars> required")?,
                    )?;
                    write_wallet(&kp)?;
                    println!("imported {} -> {}", kp.address(), path);
                    Ok(())
                }
                _ => {
                    let kp = Keypair::from_secret_hex(&wallet_secret()?)?;
                    let rpc_url = flags
                        .get("rpc")
                        .cloned()
                        .unwrap_or_else(|| "http://127.0.0.1:9933".into());
                    let mut rows = vec![
                        ("address".to_string(), kp.address()),
                        ("key file".to_string(), path.clone()),
                    ];
                    let mut staked_now: f64 = 0.0;
                    let mut online = false;
                    if let Ok(acct) = rpc_call(
                        &rpc_url,
                        "inaz_getAccount",
                        serde_json::json!({ "address": kp.address() }),
                    ) {
                        online = true;
                        rows.push((
                            "balance".into(),
                            format!(
                                "{} INAZ",
                                acct["balanceInaz"]
                                    .as_str()
                                    .or_else(|| acct["balanceFormatted"].as_str())
                                    .unwrap_or("?")
                            ),
                        ));
                        rows.push((
                            "staked".into(),
                            format!(
                                "{} INAZ",
                                acct["stakedInaz"]
                                    .as_str()
                                    .or_else(|| acct["stakedFormatted"].as_str())
                                    .unwrap_or("?")
                            ),
                        ));
                        staked_now = acct["stakedInaz"]
                            .as_str()
                            .or_else(|| acct["stakedFormatted"].as_str())
                            .and_then(|s| s.replace(',', "").parse::<f64>().ok())
                            .unwrap_or(0.0);
                    } else {
                        rows.push(("node".into(), format!("offline at {}", rpc_url)));
                    }
                    if flags.contains_key("reveal") {
                        rows.push(("secret".into(), kp.secret_hex()));
                    }
                    ui::panel("wallet", &rows);
                    // At-a-glance table: is my node usable right now?
                    ui::status_table(&[
                        ui::StatusRow {
                            label: "local node",
                            value: if online {
                                format!("reachable at {}", rpc_url)
                            } else {
                                format!("unreachable at {}", rpc_url)
                            },
                            good: Some(online),
                        },
                        ui::StatusRow {
                            label: "validating",
                            value: if staked_now >= 1000.0 {
                                "yes — stake meets the 1000 INAZ minimum".into()
                            } else {
                                "no — stake at least 1000 INAZ".into()
                            },
                            good: Some(staked_now >= 1000.0),
                        },
                    ]);
                    ui::dashboard_link(&kp.address());
                    ui::commands(staked_now >= 1000.0);
                    Ok(())
                }
            }
        }

        // Leave the validator set: unbond the whole stake in one call.
        "exit" => {
            let rpc_url = flags
                .get("rpc")
                .cloned()
                .unwrap_or_else(|| "http://127.0.0.1:9933".into());
            let kp = Keypair::from_secret_hex(
                &flags
                    .get("key")
                    .filter(|k| !k.is_empty())
                    .cloned()
                    .map(Ok)
                    .unwrap_or_else(wallet_secret)?,
            )?;
            let acct = rpc_call(
                &rpc_url,
                "inaz_getAccount",
                serde_json::json!({ "address": kp.address() }),
            )?;
            let staked: u128 = acct["staked"]
                .as_u64()
                .map(|v| v as u128)
                .or_else(|| acct["staked"].as_str().and_then(|s| s.parse().ok()))
                .unwrap_or(0);
            if staked == 0 {
                return Err("nothing staked on this account".into());
            }
            let nonce = acct["pendingNonce"]
                .as_u64()
                .or_else(|| acct["nonce"].as_u64())
                .unwrap_or(0);
            let mut tx = Transaction {
                kind: TxKind::Unstake,
                from_pubkey: kp.pubkey_hex(),
                to: kp.address(),
                amount: staked,
                fee: MIN_FEE,
                nonce,
                chain_id: CHAIN_ID,
                payload: None,
                signature: String::new(),
            };
            tx.signature = kp.sign_hex(&tx.signing_bytes());
            let res = rpc_call(
                &rpc_url,
                "inaz_sendTransaction",
                serde_json::json!({ "tx": tx }),
            )?;
            println!(
                "exit submitted: {} INAZ unbonding ({})",
                format_inaz(staked),
                res["hash"].as_str().unwrap_or("?")
            );
            println!("Keep the node running until the unbonding period ends, or you can be jailed.");
            Ok(())
        }

        "send" | "stake" | "unstake" => {
            let rpc_url = flags
                .get("rpc")
                .cloned()
                .unwrap_or_else(|| "http://127.0.0.1:9933".into());
            let kp = Keypair::from_secret_hex(
                &flags
                    .get("key")
                    .filter(|k| !k.is_empty())
                    .cloned()
                    .map(Ok)
                    .unwrap_or_else(wallet_secret)?,
            )?;
            let amount = parse_inaz(flags.get("amount").ok_or("--amount required")?)?;
            let to = match cmd.as_str() {
                "send" => flags.get("to").ok_or("--to required")?.clone(),
                _ => kp.address(),
            };
            let acct = rpc_call(
                &rpc_url,
                "inaz_getAccount",
                serde_json::json!({ "address": kp.address() }),
            )?;
            let nonce = acct["pendingNonce"]
                .as_u64()
                .or_else(|| acct["nonce"].as_u64())
                .unwrap_or(0);
            let fee = flags
                .get("fee")
                .map(|f| parse_inaz(f))
                .transpose()?
                .unwrap_or(MIN_FEE);
            let kind = match cmd.as_str() {
                "stake" => TxKind::Stake,
                "unstake" => TxKind::Unstake,
                _ => TxKind::Transfer,
            };
            let mut tx = Transaction {
                kind,
                from_pubkey: kp.pubkey_hex(),
                to,
                amount,
                fee,
                nonce,
                chain_id: CHAIN_ID,
                payload: None,
                signature: String::new(),
            };
            tx.signature = kp.sign_hex(&tx.signing_bytes());
            let res = rpc_call(
                &rpc_url,
                "inaz_sendTransaction",
                serde_json::json!({ "tx": tx }),
            )?;
            println!("submitted: {}", res["hash"].as_str().unwrap_or("?"));
            Ok(())
        }

        "tokens" => {
            let rpc_url = flags
                .get("rpc")
                .cloned()
                .unwrap_or_else(|| "http://127.0.0.1:9933".into());
            let res = rpc_call(&rpc_url, "inaz_tokens", serde_json::json!({}))?;
            println!("tokens        {}", res["count"]);
            println!(
                "creation fee  {} INAZ",
                res["creationFeeInaz"].as_str().unwrap_or("0")
            );
            if let Some(list) = res["tokens"].as_array() {
                for t in list {
                    println!(
                        "  {}  {:<10} {:<24} supply {}  holders {}  {}",
                        t["id"].as_str().unwrap_or(""),
                        t["symbol"].as_str().unwrap_or(""),
                        t["name"].as_str().unwrap_or(""),
                        t["supplyFormatted"].as_str().unwrap_or("0"),
                        t["holders"],
                        if t["mintable"].as_bool().unwrap_or(false) {
                            "mintable"
                        } else {
                            "fixed supply"
                        },
                    );
                }
            }
            Ok(())
        }

        "token-balance" => {
            let rpc_url = flags
                .get("rpc")
                .cloned()
                .unwrap_or_else(|| "http://127.0.0.1:9933".into());
            let address = flags.get("address").ok_or("--address required")?.clone();
            let res = rpc_call(
                &rpc_url,
                "inaz_tokenHoldings",
                serde_json::json!({ "address": address }),
            )?;
            let empty = Vec::new();
            let list = res["holdings"].as_array().unwrap_or(&empty);
            if list.is_empty() {
                println!("{} holds no native tokens", address);
            }
            for h in list {
                println!(
                    "  {} {}  ({})",
                    h["balanceFormatted"].as_str().unwrap_or("0"),
                    h["symbol"].as_str().unwrap_or(""),
                    h["token"].as_str().unwrap_or(""),
                );
            }
            Ok(())
        }

        "token-create" | "token-mint" | "token-send" | "token-burn" => {
            let rpc_url = flags
                .get("rpc")
                .cloned()
                .unwrap_or_else(|| "http://127.0.0.1:9933".into());
            let kp = Keypair::from_secret_hex(flags.get("key").ok_or("--key required")?)?;
            let fee = flags
                .get("fee")
                .map(|f| parse_inaz(f))
                .transpose()?
                .unwrap_or(MIN_FEE);
            let acct = rpc_call(
                &rpc_url,
                "inaz_getAccount",
                serde_json::json!({ "address": kp.address() }),
            )?;
            let nonce = acct["pendingNonce"]
                .as_u64()
                .or_else(|| acct["nonce"].as_u64())
                .unwrap_or(0);

            let (kind, payload, amount, to) = match cmd.as_str() {
                "token-create" => {
                    let symbol =
                        tokens::normalize_symbol(flags.get("symbol").ok_or("--symbol required")?)?;
                    let name = flags.get("name").cloned().unwrap_or_else(|| symbol.clone());
                    let decimals: u8 = flags
                        .get("decimals")
                        .and_then(|d| d.parse().ok())
                        .unwrap_or(9);
                    let mintable = flags.get("mintable").map(|v| v != "false").unwrap_or(false);
                    let supply = tokens::parse_units(
                        flags.get("supply").map(|s| s.as_str()).unwrap_or("0"),
                        decimals,
                    )?;
                    let p = Payload {
                        token: String::new(),
                        symbol,
                        name,
                        decimals,
                        mintable,
                        ..Default::default()
                    };
                    (TxKind::CreateToken, Some(p), supply, kp.address())
                }
                _ => {
                    let token = flags.get("token").ok_or("--token required")?.clone();
                    let info = rpc_call(
                        &rpc_url,
                        "inaz_getToken",
                        serde_json::json!({ "token": token }),
                    )?;
                    let decimals = info["decimals"].as_u64().unwrap_or(9) as u8;
                    let amount = tokens::parse_units(
                        flags.get("amount").ok_or("--amount required")?,
                        decimals,
                    )?;
                    let to = match cmd.as_str() {
                        "token-burn" => kp.address(),
                        _ => flags.get("to").ok_or("--to required")?.clone(),
                    };
                    let kind = match cmd.as_str() {
                        "token-mint" => TxKind::MintToken,
                        "token-burn" => TxKind::BurnToken,
                        _ => TxKind::TokenTransfer,
                    };
                    let p = Payload {
                        token,
                        ..Default::default()
                    };
                    (kind, Some(p), amount, to)
                }
            };

            let mut tx = Transaction {
                kind,
                from_pubkey: kp.pubkey_hex(),
                to,
                amount,
                fee,
                nonce,
                chain_id: CHAIN_ID,
                payload,
                signature: String::new(),
            };
            tx.signature = kp.sign_hex(&tx.signing_bytes());
            let res = rpc_call(
                &rpc_url,
                "inaz_sendTransaction",
                serde_json::json!({ "tx": tx }),
            )?;
            println!("submitted: {}", res["hash"].as_str().unwrap_or("?"));
            if cmd == "token-create" {
                println!(
                    "token id:  {} (creation fee {} INAZ)",
                    tokens::token_id(
                        &kp.address(),
                        nonce,
                        &tokens::normalize_symbol(flags.get("symbol").unwrap())?
                    ),
                    format_inaz(tokens::TOKEN_CREATION_FEE)
                );
            }
            Ok(())
        }

        "deploy" | "call" => {
            let rpc_url = flags
                .get("rpc")
                .cloned()
                .unwrap_or_else(|| "http://127.0.0.1:9933".into());
            let kp = Keypair::from_secret_hex(flags.get("key").ok_or("--key required")?)?;
            let value = flags
                .get("value")
                .map(|v| parse_inaz(v))
                .transpose()?
                .unwrap_or(0);
            let fee = flags
                .get("fee")
                .map(|f| parse_inaz(f))
                .transpose()?
                .unwrap_or(MIN_FEE * 200);
            let acct = rpc_call(
                &rpc_url,
                "inaz_getAccount",
                serde_json::json!({ "address": kp.address() }),
            )?;
            let nonce = acct["pendingNonce"]
                .as_u64()
                .or_else(|| acct["nonce"].as_u64())
                .unwrap_or(0);
            let (kind, to, payload) = if cmd == "deploy" {
                let path = flags.get("wasm").ok_or("--wasm FILE required")?;
                let raw = std::fs::read(path).map_err(|e| format!("read {}: {}", path, e))?;
                // .wat source is assembled locally so only bytecode ever hits the chain.
                let code = if path.ends_with(".wat") {
                    wat::parse_bytes(&raw)
                        .map_err(|e| format!("bad wat: {}", e))?
                        .to_vec()
                } else {
                    raw
                };
                let p = Payload {
                    code: hex::encode(&code),
                    ..Default::default()
                };
                println!(
                    "code {} bytes, deploy fee {} INAZ",
                    code.len(),
                    format_inaz(contracts::DEPLOY_FEE)
                );
                (TxKind::DeployContract, kp.address(), Some(p))
            } else {
                let addr = flags
                    .get("contract")
                    .ok_or("--contract ADDR required")?
                    .clone();
                let args = flags.get("args").cloned().unwrap_or_default();
                (
                    TxKind::CallContract,
                    addr,
                    Some(Payload {
                        args,
                        ..Default::default()
                    }),
                )
            };
            let mut tx = Transaction {
                kind,
                from_pubkey: kp.pubkey_hex(),
                to,
                amount: value,
                fee,
                nonce,
                chain_id: CHAIN_ID,
                payload,
                signature: String::new(),
            };
            tx.signature = kp.sign_hex(&tx.signing_bytes());
            let res = rpc_call(
                &rpc_url,
                "inaz_sendTransaction",
                serde_json::json!({ "tx": tx }),
            )?;
            let hash = res["hash"].as_str().unwrap_or("?").to_string();
            println!("submitted: {}", hash);
            if cmd == "deploy" {
                println!(
                    "contract:  {}",
                    res["contract"].as_str().unwrap_or("(pending)")
                );
            }
            println!("receipt:   inazuma receipt --hash {}", hash);
            Ok(())
        }

        "query" => {
            let rpc_url = flags
                .get("rpc")
                .cloned()
                .unwrap_or_else(|| "http://127.0.0.1:9933".into());
            let address = flags
                .get("contract")
                .ok_or("--contract ADDR required")?
                .clone();
            let args = flags.get("args").cloned().unwrap_or_default();
            let res = rpc_call(
                &rpc_url,
                "inaz_query",
                serde_json::json!({ "address": address, "args": args }),
            )?;
            println!("ok         {}", res["ok"]);
            println!("return     {}", res["returnHex"].as_str().unwrap_or(""));
            println!("as text    {}", res["returnText"].as_str().unwrap_or(""));
            println!("fuel used  {}", res["fuelUsed"]);
            if let Some(logs) = res["logs"].as_array() {
                for l in logs {
                    println!("  log: {}", l.as_str().unwrap_or(""));
                }
            }
            if let Some(err) = res["error"].as_str() {
                println!("error      {}", err);
            }
            Ok(())
        }

        "receipt" => {
            let rpc_url = flags
                .get("rpc")
                .cloned()
                .unwrap_or_else(|| "http://127.0.0.1:9933".into());
            let hash = flags.get("hash").ok_or("--hash required")?.clone();
            let res = rpc_call(
                &rpc_url,
                "inaz_getReceipt",
                serde_json::json!({ "hash": hash }),
            )?;
            println!("{}", serde_json::to_string_pretty(&res).unwrap_or_default());
            Ok(())
        }

        "contracts" => {
            let rpc_url = flags
                .get("rpc")
                .cloned()
                .unwrap_or_else(|| "http://127.0.0.1:9933".into());
            let res = rpc_call(&rpc_url, "inaz_contracts", serde_json::json!({}))?;
            println!("contracts {}", res["count"]);
            if let Some(list) = res["contracts"].as_array() {
                for c in list {
                    println!(
                        "  {}  {} bytes  calls {}  height {}  by {}",
                        c["address"].as_str().unwrap_or(""),
                        c["codeSize"],
                        c["calls"],
                        c["createdHeight"],
                        c["creator"].as_str().unwrap_or(""),
                    );
                }
            }
            Ok(())
        }

        "bench" => {
            let rpc_url = flags
                .get("rpc")
                .cloned()
                .unwrap_or_else(|| "http://127.0.0.1:9933".into());
            let kp = Keypair::from_secret_hex(flags.get("key").ok_or("--key required")?)?;
            let count: u64 = flags
                .get("count")
                .and_then(|c| c.parse().ok())
                .unwrap_or(1000);
            let batch: usize = flags
                .get("batch")
                .and_then(|c| c.parse().ok())
                .unwrap_or(500);
            let to = flags.get("to").cloned().unwrap_or_else(|| kp.address());
            let acct = rpc_call(
                &rpc_url,
                "inaz_getAccount",
                serde_json::json!({ "address": kp.address() }),
            )?;
            let mut nonce = acct["pendingNonce"].as_u64().unwrap_or(0);

            // Sign up front so the measurement covers the node, not our signer.
            let sign_start = std::time::Instant::now();
            let mut txs = Vec::with_capacity(count as usize);
            for _ in 0..count {
                let mut tx = Transaction {
                    kind: TxKind::Transfer,
                    from_pubkey: kp.pubkey_hex(),
                    to: to.clone(),
                    amount: 1_000,
                    fee: MIN_FEE,
                    nonce,
                    chain_id: CHAIN_ID,
                    payload: None,
                    signature: String::new(),
                };
                tx.signature = kp.sign_hex(&tx.signing_bytes());
                nonce += 1;
                txs.push(tx);
            }
            let sign_ms = sign_start.elapsed().as_millis().max(1) as f64;
            println!(
                "signed     {} txs in {:.0} ms ({:.0} sig/s client side)",
                count,
                sign_ms,
                count as f64 * 1000.0 / sign_ms
            );

            let info = rpc_call(&rpc_url, "inaz_chainInfo", serde_json::json!({}))?;
            let start_txs = info["totalTxs"].as_u64().unwrap_or(0);
            let start_height = info["height"].as_u64().unwrap_or(0);

            let submit_start = std::time::Instant::now();
            let mut ok = 0u64;
            for chunk in txs.chunks(batch.max(1)) {
                match rpc_call(
                    &rpc_url,
                    "inaz_sendTransactions",
                    serde_json::json!({ "txs": chunk }),
                ) {
                    Ok(res) => ok += res["accepted"].as_u64().unwrap_or(0),
                    Err(e) => eprintln!("[bench] batch rejected: {}", e),
                }
            }
            let submit_ms = submit_start.elapsed().as_millis().max(1) as f64;
            println!(
                "submitted  {}/{} txs in {:.0} ms ({:.0} tx/s into mempool)",
                ok,
                count,
                submit_ms,
                ok as f64 * 1000.0 / submit_ms
            );

            // What actually matters: how fast the chain executes and finalises them.
            let exec_start = std::time::Instant::now();
            loop {
                std::thread::sleep(std::time::Duration::from_millis(50));
                let info = rpc_call(&rpc_url, "inaz_chainInfo", serde_json::json!({}))?;
                let done = info["totalTxs"]
                    .as_u64()
                    .unwrap_or(0)
                    .saturating_sub(start_txs);
                let mempool = info["mempool"].as_u64().unwrap_or(0);
                let timeout = exec_start.elapsed().as_secs() > 120;
                if (done >= ok && mempool == 0) || timeout {
                    let ms = exec_start.elapsed().as_millis().max(1) as f64;
                    let blocks = info["height"]
                        .as_u64()
                        .unwrap_or(0)
                        .saturating_sub(start_height);
                    println!(
                        "executed   {} txs across {} blocks in {:.0} ms",
                        done, blocks, ms
                    );
                    println!(
                        "throughput {:.0} tx/s (executed and finalised)",
                        done as f64 * 1000.0 / ms
                    );
                    if blocks > 0 {
                        println!("density    {} txs per block avg", done / blocks);
                    }
                    if timeout {
                        println!(
                            "note       stopped at the 120s cap, {} still queued",
                            mempool
                        );
                    }
                    break;
                }
            }
            Ok(())
        }

        _ => {
            ui::banner();
            println!("Inazuma node (chain id {})\n", CHAIN_ID);
            println!("  wallet-new                                create + save a validator wallet");
            println!("  wallet-import --key HEX                   import an existing secret key");
            println!("  wallet [--reveal]                         show address, balance and stake");
            println!("  exit                                      unbond everything and leave the set");
            println!("  keygen                                    create a new INAZ keypair");
            println!("  init    --data DIR --genesis FILE         seal genesis block 0");
            println!("  run     --data DIR --key HEX --rpc ADDR   run the node + JSON-RPC");
            println!("          [--rpc-keys K1,K2] [--rpc-admin-keys K] [--rpc-require-auth] [--rpc-trust-proxy]");
            println!("  send    --key HEX --to ADDR --amount N    send INAZ");
            println!("  stake   --key HEX --amount N              stake INAZ");
            println!("  unstake --key HEX --amount N              unstake INAZ");
            println!("  status  [--rpc URL]                       node height, peers and sync state");
            println!("  validators                                show the validator set");
            println!("  balance --address ADDR                    read an account");
            println!("  token-create --key HEX --symbol S --name N --supply N [--decimals 9] [--mintable true]");
            println!("  token-mint   --key HEX --token ID --to ADDR --amount N");
            println!("  token-send   --key HEX --token ID --to ADDR --amount N");
            println!("  token-burn   --key HEX --token ID --amount N");
            println!("  tokens                                    list native tokens");
            println!("  token-balance --address ADDR              token holdings of an address");
            println!("  deploy  --key HEX --wasm FILE [--value N]  deploy a wasm contract");
            println!("  call    --key HEX --contract ADDR [--args HEX] [--value N] [--fee N]");
            println!("  query   --contract ADDR [--args HEX]      read-only contract call");
            println!("  contracts                                 list deployed contracts");
            println!(
                "  bench   --key HEX --count N               submit N txs and measure throughput"
            );
            Ok(())
        }
    }
}

/// The producer key comes from --key, INAZUMA_KEY, or a generated node key on disk.
fn producer_key(flags: &HashMap<String, String>, data: &str) -> Result<Keypair, String> {
    if let Some(k) = flags.get("key").filter(|k| !k.is_empty()) {
        return Keypair::from_secret_hex(k);
    }
    if let Ok(k) = wallet_secret() {
        return Keypair::from_secret_hex(&k);
    }
    if let Ok(k) = std::env::var("INAZUMA_KEY") {
        if !k.trim().is_empty() {
            return Keypair::from_secret_hex(&k);
        }
    }
    let path = format!("{}.nodekey", data.trim_end_matches('/'));
    if let Ok(existing) = std::fs::read_to_string(&path) {
        return Keypair::from_secret_hex(&existing);
    }
    let kp = Keypair::generate();
    std::fs::write(&path, kp.secret_hex()).map_err(|e| e.to_string())?;
    println!("[key] generated node key at {} ({})", path, kp.address());
    Ok(kp)
}

/// Where the operator wallet lives. One file, one format, owned by the CLI.
fn wallet_path() -> String {
    if let Ok(p) = std::env::var("INAZ_WALLET") {
        return p;
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    format!("{}/.inazuma/validator.env", home)
}

/// Reads the wallet secret from INAZ_KEY or the wallet file. The file is
/// tolerant on purpose: `export INAZ_KEY='hex'`, `INAZ_KEY=hex`,
/// `secret key: hex`, or a bare hex line all work, so a hand-edited file or old
/// keygen output never blocks the operator.
fn wallet_secret() -> Result<String, String> {
    if let Ok(k) = std::env::var("INAZ_KEY") {
        if k.trim().len() == 64 {
            return Ok(k.trim().to_string());
        }
    }
    let path = wallet_path();
    let text = std::fs::read_to_string(&path)
        .map_err(|_| format!("no wallet at {} — run `inazuma wallet-new`", path))?;
    for line in text.lines() {
        let cleaned: String = line
            .trim()
            .trim_start_matches("export ")
            .split(['=', ':'])
            .last()
            .unwrap_or("")
            .trim()
            .trim_matches(['\'', '"', ' '])
            .to_string();
        if cleaned.len() == 64 && cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(cleaned.to_lowercase());
        }
    }
    Err(format!(
        "{} has no 64-hex secret key — run `inazuma wallet-new` or `inazuma wallet-import --key HEX`",
        path
    ))
}

/// Writes the wallet in the one format every command understands.
///
/// The secret never touches a world-readable file: it is written to a temp file
/// created with 0600 (Unix) or inside the user-private wallet directory
/// (elsewhere), then renamed over the target. Renaming is atomic, so there is no
/// window where a half-written or permissive copy of the key exists on disk.
fn write_wallet(kp: &Keypair) -> Result<(), String> {
    let path = wallet_path();
    if let Some(dir) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    let body = format!(
        "# Inazuma validator wallet — keep this file private\nexport INAZ_KEY='{}'\nexport INAZ_ADDRESS='{}'\n",
        kp.secret_hex(),
        kp.address()
    );
    let tmp = format!("{}.tmp", path);
    let _ = std::fs::remove_file(&tmp);
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(|e| e.to_string())?;
        f.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    #[cfg(not(unix))]
    println!(
        "note: {} holds your secret key in plaintext. On Windows, restrict it with\n      icacls \"{}\" /inheritance:r /grant:r \"%USERNAME%:F\"",
        path, path
    );
    Ok(())
}

/// JSON-RPC client supporting both local HTTP and public HTTPS endpoints.
fn rpc_call(
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let endpoint = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("http://{}", url)
    };
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
        .to_string();
    let response = ureq::post(&endpoint)
        .set("Content-Type", "application/json")
        .send_string(&body)
        .map_err(|e| format!("RPC request to {} failed: {}", endpoint, e))?;
    let response_body = response
        .into_string()
        .map_err(|e| format!("could not read response from {}: {}", endpoint, e))?;
    let parsed: serde_json::Value = serde_json::from_str(&response_body)
        .map_err(|e| format!("bad JSON response from {}: {}", endpoint, e))?;
    if let Some(err) = parsed.get("error") {
        return Err(err["message"].as_str().unwrap_or("rpc error").to_string());
    }
    Ok(parsed
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}
