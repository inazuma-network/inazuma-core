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
mod consensus;
mod contracts;
mod crypto;
mod events;
mod fees;
mod fuzz;
mod journal;
mod limits;
mod mempool;
mod p2p;
mod qos;
mod rpc;
mod rpcauth;
mod simulate;
mod slashing;
mod smt;
mod snapshot;
mod staking;
mod state;
mod tokens;
mod transport;
mod types;
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

            println!("=== Inazuma node ===");
            println!("chain id     {}", node.genesis.chain_id);
            println!("producer     {}", node.producer.address());
            println!("node key     {}", node_id.pubkey_hex());
            println!(
                "p2p security encrypted INSC1 ({}), allowlist {}",
                if network.require_encryption {
                    "required"
                } else {
                    "preferred"
                },
                if network.allowed_ids.is_empty() {
                    "off".to_string()
                } else {
                    format!("{} keys", network.allowed_ids.len())
                }
            );
            println!("block time   {} ms", block_time);
            println!("height       {}", node.store.tip_height().unwrap_or(0));
            println!(
                "supply       {} INAZ",
                format_inaz(node.store.total_supply())
            );
            println!(
                "staked       {} INAZ across {} validators",
                format_inaz(node.store.total_staked()),
                node.validators().len()
            );
            println!(
                "min stake    {} INAZ to validate",
                format_inaz(types::MIN_STAKE)
            );
            println!(
                "mode         {}",
                if replica {
                    "replica (serving only)"
                } else if node.solo() {
                    "solo (no peers)"
                } else {
                    "networked"
                }
            );
            println!(
                "ws           {}",
                if ws_addr.is_empty() {
                    "disabled".to_string()
                } else {
                    format!("ws://{}", ws_addr)
                }
            );
            println!("finalized    height {}", node.store.finalized_height());
            println!(
                "base fee     {} rai (floor {} rai)",
                node.base_fee(),
                node.fee_floor()
            );
            println!(
                "state root   merkle from height {}",
                state::STATE_ROOT_V2_ACTIVATION_HEIGHT
            );

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

            loop {
                let started = std::time::Instant::now();
                match node.produce_block() {
                    Ok(Some(b)) => {
                        if !b.transactions.is_empty() {
                            println!(
                                "[block] #{} txs={} hash={}",
                                b.height,
                                b.transactions.len(),
                                &b.hash[..16]
                            );
                        }
                        p2p::announce_block(&network, &b);
                        p2p::vote_on(&node, &network, &b);
                    }
                    Ok(None) => { /* another validator's slot */ }
                    Err(e) => eprintln!("[block] error: {}", e),
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

        "send" | "stake" | "unstake" => {
            let rpc_url = flags
                .get("rpc")
                .cloned()
                .unwrap_or_else(|| "http://127.0.0.1:9933".into());
            let kp = Keypair::from_secret_hex(flags.get("key").ok_or("--key required")?)?;
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
            println!("Inazuma node (chain id {})\n", CHAIN_ID);
            println!("  keygen                                    create a new INAZ keypair");
            println!("  init    --data DIR --genesis FILE         seal genesis block 0");
            println!("  run     --data DIR --key HEX --rpc ADDR   run the node + JSON-RPC");
            println!("          [--rpc-keys K1,K2] [--rpc-admin-keys K] [--rpc-require-auth] [--rpc-trust-proxy]");
            println!("  send    --key HEX --to ADDR --amount N    send INAZ");
            println!("  stake   --key HEX --amount N              stake INAZ");
            println!("  unstake --key HEX --amount N              unstake INAZ");
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

/// Minimal JSON-RPC client over raw HTTP, so the CLI needs no HTTP dependency.
fn rpc_call(
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    use std::io::{Read, Write};
    let stripped = url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let (host_port, path) = match stripped.split_once('/') {
        Some((h, p)) => (h, format!("/{}", p)),
        None => (stripped, "/".to_string()),
    };
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
        .to_string();
    let mut stream = std::net::TcpStream::connect(host_port).map_err(|e| e.to_string())?;
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host_port, body.len(), body
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .map_err(|e| e.to_string())?;
    let json_start = resp.find("\r\n\r\n").ok_or("bad response")? + 4;
    let parsed: serde_json::Value =
        serde_json::from_str(&resp[json_start..]).map_err(|e| format!("bad json: {}", e))?;
    if let Some(err) = parsed.get("error") {
        return Err(err["message"].as_str().unwrap_or("rpc error").to_string());
    }
    Ok(parsed
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}
