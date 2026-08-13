//! Inazuma JSON-RPC: a small HTTP server the website, wallets and CLI talk to.

use crate::chain::Node;
use crate::contracts::{self, Contract};
use crate::crypto::is_valid_address;
use crate::fees::{self, FEE_MARKET_ACTIVATION_HEIGHT};
use crate::limits::{ConnGuard, IpConnCounter};
use crate::rpcauth::{self, RpcConfig, Tier};
use crate::staking;
use crate::slashing::{self, Evidence};
use crate::tokens::{self, format_units};
use crate::types::{
    format_inaz, Block, Payload, Transaction, TxKind, DOWNTIME_JAIL_BLOCKS, DOWNTIME_JAIL_STREAK,
    DOWNTIME_REPEAT_BURN_BPS, EQUIVOCATION_CORRELATION_FACTOR, EQUIVOCATION_MIN_BURN_PCT,
    EVIDENCE_MAX_AGE_BLOCKS, MIN_STAKE, REPORTER_BOUNTY_PCT, SLASHING_ACTIVATION_HEIGHT,
    TOMBSTONE_HEIGHT, UNBONDING_BLOCKS,
};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

/// Public RPC abuse limits. Generous for real users, fatal for a spam loop.
const RPC_MAX_LIVE_CONNS: usize = 512;
/// One host may not hold more than this share of the connection table.
const RPC_MAX_CONNS_PER_IP: usize = 32;
const RPC_MAX_BODY: usize = 4 * 1024 * 1024;
/// Largest bulk submission accepted in one call.
const MAX_BATCH_TXS: usize = 5_000;

pub fn serve(node: Arc<Node>, addr: &str) -> Result<(), String> {
    serve_with(node, addr, Arc::new(RpcConfig::public()))
}

pub fn serve_with(node: Arc<Node>, addr: &str, cfg: Arc<RpcConfig>) -> Result<(), String> {
    let listener = TcpListener::bind(addr).map_err(|e| e.to_string())?;
    println!("[rpc] listening on http://{}", addr);
    println!(
        "[rpc] auth {} ({} keys), rate {}/s anon and {}/s keyed, {} conns per ip",
        if cfg.require_auth { "required" } else if cfg.auth_enabled() { "optional" } else { "off" },
        cfg.key_count(),
        rpcauth::ANON_RATE,
        rpcauth::KEY_RATE,
        RPC_MAX_CONNS_PER_IP
    );
    let conns = Arc::new(ConnGuard::new(RPC_MAX_LIVE_CONNS));
    let per_ip = Arc::new(IpConnCounter::new(RPC_MAX_CONNS_PER_IP));
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let n = Arc::clone(&node);
                let cg = Arc::clone(&conns);
                let ipc = Arc::clone(&per_ip);
                let cfg = Arc::clone(&cfg);
                std::thread::spawn(move || {
                    let Some(_ticket) = cg.try_acquire() else {
                        return; // at capacity: drop instead of queueing forever
                    };
                    let ip = s.peer_addr().map(|p| p.ip()).ok();
                    // Socket-level fairness: one host cannot occupy every slot.
                    let _ip_ticket = match ip {
                        Some(ip) => match ipc.try_acquire(ip) {
                            Some(t) => Some(t),
                            None => return,
                        },
                        None => None,
                    };
                    if let Err(e) = handle_conn(n, s, cfg, ip) {
                        eprintln!("[rpc] connection error: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("[rpc] accept error: {}", e),
        }
    }
    Ok(())
}

fn handle_conn(
    node: Arc<Node>,
    mut stream: TcpStream,
    cfg: Arc<RpcConfig>,
    peer_ip: Option<std::net::IpAddr>,
) -> Result<(), String> {
    stream.set_read_timeout(Some(Duration::from_secs(15))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(15))).ok();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut header_end = None;
    while header_end.is_none() {
        let read = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if read == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..read]);
        header_end = find_header_end(&buf);
        if buf.len() > RPC_MAX_BODY {
            return Err("request too large".into());
        }
    }
    let he = header_end.unwrap();
    let head = String::from_utf8_lossy(&buf[..he]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("").to_string();
    let mut content_length = 0usize;
    let mut credential: Option<String> = None;
    let mut forwarded: Option<std::net::IpAddr> = None;
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
        // Header names are case-insensitive; values are not, so slice the raw line.
        if lower.starts_with("authorization:") {
            let raw = line[line.find(':').map(|i| i + 1).unwrap_or(0)..].trim();
            let token = raw.strip_prefix("Bearer ").or_else(|| raw.strip_prefix("bearer ")).unwrap_or(raw);
            if !token.is_empty() {
                credential = Some(token.to_string());
            }
        } else if lower.starts_with("x-api-key:") {
            let raw = line[line.find(':').map(|i| i + 1).unwrap_or(0)..].trim();
            if !raw.is_empty() {
                credential = Some(raw.to_string());
            }
        } else if lower.starts_with("x-forwarded-for:") && cfg.trust_proxy {
            let raw = line[line.find(':').map(|i| i + 1).unwrap_or(0)..].trim();
            forwarded = raw.split(',').next().and_then(|s| s.trim().parse().ok());
        }
    }
    let mut body = buf[he + 4..].to_vec();
    if content_length > RPC_MAX_BODY {
        return respond(&mut stream, 413, &json!({ "error": "body too large" }).to_string());
    }
    while body.len() < content_length {
        let read = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }

    let method_path: Vec<&str> = request_line.split_whitespace().collect();
    let http_method = method_path.first().copied().unwrap_or("");
    let path = method_path.get(1).copied().unwrap_or("/");

    if http_method == "OPTIONS" {
        return respond(&mut stream, 204, "");
    }

    let tier = cfg.tier_for(credential.as_deref());
    let client_ip = forwarded
        .or(peer_ip)
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

    if http_method == "GET" {
        // Health/discovery stays open but is still metered.
        if !cfg.charge(client_ip, tier, credential.as_deref(), 1.0) {
            return respond(&mut stream, 429, &json!({ "error": "rate limited" }).to_string());
        }
        let payload = match path {
            "/health" => json!({ "ok": true, "height": node.store.tip_height().unwrap_or(0) }),
            _ => json!({
                "chain": node.genesis.chain_name,
                "chainId": node.genesis.chain_id,
                "symbol": node.genesis.symbol,
                "rpc": "POST JSON-RPC 2.0 to /",
                "auth": if cfg.require_auth { "api key required" } else { "open" },
            }),
        };
        return respond(&mut stream, 200, &payload.to_string());
    }

    let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or(json!({}));

    // 1. Authentication: a closed endpoint refuses unknown callers outright.
    if cfg.require_auth && tier == Tier::Anonymous {
        return respond(
            &mut stream,
            401,
            &json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32001, "message": "api key required" } })
                .to_string(),
        );
    }
    // 2. Authorization: operator-only methods need an admin key.
    if rpcauth::PRIVILEGED_METHODS.contains(&method) && cfg.auth_enabled() && tier != Tier::Admin {
        return respond(
            &mut stream,
            403,
            &json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32002, "message": "admin key required" } })
                .to_string(),
        );
    }
    // 3. Weighted throttle: expensive calls spend more of the caller's budget.
    let cost = rpcauth::method_cost(method, &params);
    if !cfg.charge_weighted(&node.store, client_ip, tier, credential.as_deref(), cost) {
        return respond(
            &mut stream,
            429,
            &json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": -32005, "message": "rate limited", "data": { "tier": tier.label(), "cost": cost } }
            })
            .to_string(),
        );
    }

    let out = match dispatch_metered(&node, method, &params, &cfg, tier) {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(msg) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": msg } }),
    };
    respond(&mut stream, 200, &out.to_string())
}

/// Per-account throttle for the two admission methods, applied before the node
/// spends CPU on signature verification. Keyed on the signer, so one account
/// cannot flood the mempool from a thousand IPs.
pub fn dispatch_metered(
    node: &Arc<Node>,
    method: &str,
    params: &Value,
    cfg: &RpcConfig,
    tier: Tier,
) -> Result<Value, String> {
    match method {
        "inaz_sendTransaction" => {
            let raw = params.get("tx").cloned().unwrap_or_else(|| params.clone());
            if let Some(sender) = raw.get("from_pubkey").and_then(|v| v.as_str()) {
                if !cfg.charge_account(sender, 1) {
                    return Err(format!("account {} is submitting too fast", sender));
                }
            }
        }
        "inaz_sendTransactions" => {
            if let Some(list) = params.get("txs").and_then(|v| v.as_array()) {
                let mut per_sender: std::collections::HashMap<&str, usize> =
                    std::collections::HashMap::new();
                for tx in list {
                    if let Some(s) = tx.get("from_pubkey").and_then(|v| v.as_str()) {
                        *per_sender.entry(s).or_insert(0) += 1;
                    }
                }
                for (sender, count) in per_sender {
                    if !cfg.charge_account(sender, count) {
                        return Err(format!("account {} is submitting too fast", sender));
                    }
                }
            }
        }
        "inaz_rpcLimits" => {
            return Ok(json!({
                "tier": tier.label(),
                "authEnabled": cfg.auth_enabled(),
                "authRequired": cfg.require_auth,
                "trustProxy": cfg.trust_proxy,
                "anonRatePerSec": rpcauth::ANON_RATE,
                "anonBurst": rpcauth::ANON_BURST,
                "keyRatePerSec": rpcauth::KEY_RATE,
                "keyBurst": rpcauth::KEY_BURST,
                "accountTxPerSec": rpcauth::ACCOUNT_TX_RATE,
                "maxConnsPerIp": RPC_MAX_CONNS_PER_IP,
                "maxLiveConns": RPC_MAX_LIVE_CONNS,
                "stakeWeighted": !cfg.qos.is_empty(),
                "boundKeys": cfg.qos.len(),
                "stakeSharePct": cfg.qos.share_pct(&node.store, credential_hint(params)),
                "stakeMultiplier": cfg.qos.multiplier(&node.store, credential_hint(params)),
                "maxStakeMultiplier": crate::qos::MAX_STAKE_MULTIPLIER,
                "liveSubscriptions": node.events.len(),
                "trackedKeys": cfg.keyed.tracked(),
                "trackedAccounts": cfg.accounts.tracked(),
            }));
        }
        _ => {}
    }
    dispatch(node, method, params)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn respond(stream: &mut TcpStream, status: u16, body: &str) -> Result<(), String> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nConnection: close\r\n\r\n",
        status,
        reason,
        body.len()
    );
    stream.write_all(head.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())
}

fn block_json(b: &Block) -> Value {
    json!({
        "height": b.height,
        "hash": b.hash,
        "parentHash": b.parent_hash,
        "timestamp": b.timestamp_ms.to_string(),
        "stateRoot": b.state_root,
        "txsRoot": b.txs_root,
        "producer": b.producer,
        "txCount": b.transactions.len(),
        "transactions": b.transactions.iter().map(tx_json).collect::<Vec<_>>(),
    })
}

fn tx_json(t: &Transaction) -> Value {
    json!({
        "hash": t.hash(),
        "kind": t.kind.label(),
        "from": t.sender().unwrap_or_default(),
        "to": t.to,
        "amount": t.amount.to_string(),
        "amountInaz": format_inaz(t.amount),
        "fee": t.fee.to_string(),
        "nonce": t.nonce,
        "payload": t.payload,
    })
}

fn token_json(t: &tokens::Token) -> Value {
    json!({
        "id": t.id,
        "symbol": t.symbol,
        "name": t.name,
        "decimals": t.decimals,
        "supply": t.supply.to_string(),
        "supplyFormatted": format_units(t.supply, t.decimals),
        "creator": t.creator,
        "mintable": t.mintable,
        "createdHeight": t.created_height,
        "holders": t.holders,
    })
}

fn contract_json(c: &Contract) -> Value {
    json!({
        "address": c.address,
        "codeHash": c.code_hash,
        "codeSize": c.code_size,
        "creator": c.creator,
        "createdHeight": c.created_height,
        "calls": c.calls,
    })
}

fn dispatch(node: &Arc<Node>, method: &str, params: &Value) -> Result<Value, String> {
    match method {
        "inaz_chainInfo" => {
            let height = node.store.tip_height().unwrap_or(0);
            Ok(json!({
                "chain": node.genesis.chain_name,
                "chainId": node.genesis.chain_id,
                "symbol": node.genesis.symbol,
                "decimals": node.genesis.decimals,
                "blockTimeMs": node.genesis.block_time_ms,
                "height": height,
                "tipHash": node.store.tip_hash(),
                "finalizedHeight": node.store.finalized_height(),
                "peers": node.peer_count(),
                "mode": if node.solo() { "solo" } else { "networked" },
                "accounts": node.store.account_count(),
                "totalTxs": node.store.tx_count(),
                "mempool": node.mempool_size(),
                "baseFee": node.base_fee().to_string(),
                "feeFloor": node.fee_floor().to_string(),
                "stateRoot": node.store.state_root_at(height),
                "totalSupply": format_inaz(node.store.total_supply()),
                "totalStaked": format_inaz(node.store.total_staked()),
                "producer": node.producer.address(),
                "validators": node.validators().len(),
                "nextLeader": node.next_leader(),
                "minStake": format_inaz(MIN_STAKE),
                "blockReward": format_inaz(staking::BLOCK_REWARD),
                "tokens": node.store.token_count(),
                "tokenCreationFee": format_inaz(tokens::TOKEN_CREATION_FEE),
                "contracts": node.store.contract_count(),
                "deployFee": format_inaz(contracts::DEPLOY_FEE),
                "vm": "wasm",
            }))
        }
        "inaz_tokens" => {
            let list = node.store.tokens();
            Ok(json!({
                "count": list.len(),
                "creationFeeInaz": format_inaz(tokens::TOKEN_CREATION_FEE),
                "tokens": list.iter().map(token_json).collect::<Vec<_>>(),
            }))
        }
        "inaz_getToken" => {
            let id = params.get("token").and_then(|v| v.as_str()).ok_or("missing token")?;
            match node.store.token(id) {
                Some(t) => {
                    let mut v = token_json(&t);
                    v["topHolders"] = json!(node
                        .store
                        .token_holders(&t.id, 20)
                        .into_iter()
                        .map(|(addr, bal)| json!({
                            "address": addr,
                            "balance": bal.to_string(),
                            "balanceFormatted": format_units(bal, t.decimals),
                        }))
                        .collect::<Vec<_>>());
                    Ok(v)
                }
                None => Ok(Value::Null),
            }
        }
        "inaz_tokenBalance" => {
            let id = params.get("token").and_then(|v| v.as_str()).ok_or("missing token")?;
            let addr = params.get("address").and_then(|v| v.as_str()).ok_or("missing address")?;
            let token = node.store.token(id).ok_or("unknown token")?;
            let bal = node.store.token_balance(id, addr);
            Ok(json!({
                "token": token.id,
                "symbol": token.symbol,
                "address": addr,
                "balance": bal.to_string(),
                "balanceFormatted": format_units(bal, token.decimals),
            }))
        }
        "inaz_tokenHoldings" => {
            let addr = params.get("address").and_then(|v| v.as_str()).ok_or("missing address")?;
            if !is_valid_address(addr) {
                return Err("invalid address".into());
            }
            Ok(json!({
                "address": addr,
                "holdings": node.store.token_holdings(addr).into_iter().map(|(t, bal)| json!({
                    "token": t.id,
                    "symbol": t.symbol,
                    "name": t.name,
                    "decimals": t.decimals,
                    "balance": bal.to_string(),
                    "balanceFormatted": format_units(bal, t.decimals),
                })).collect::<Vec<_>>(),
            }))
        }
        // Network security surface: is the encrypted transport in force, who is
        // authenticated, and how many hosts are currently banned.
        "inaz_netInfo" => {
            let net = node.gossip_handle();
            Ok(match net {
                Some(net) => json!({
                    "transport": "INSC1 (X25519 + ed25519 auth + ChaCha20-Poly1305)",
                    "encryptionRequired": net.require_encryption,
                    "nodeKey": net.id.pubkey_hex(),
                    "listen": net.listen,
                    "peers": net.peers,
                    "allowlist": net.allowed_ids.iter().cloned().collect::<Vec<_>>(),
                    "authenticatedPeers": net.book.known_identities().iter()
                        .map(|(ip, id)| json!({ "ip": ip.to_string(), "nodeKey": id }))
                        .collect::<Vec<_>>(),
                    "bannedHosts": net.book.banned_count(),
                }),
                None => json!({ "transport": "disabled", "peers": [] }),
            })
        }
        "inaz_blockNumber" => Ok(json!(node.store.tip_height().unwrap_or(0))),
        // Fee market: what a transaction must pay right now, and how the base
        // fee is trending, so wallets can quote instead of guessing.
        "inaz_feeMarket" => {
            let height = node.store.tip_height().unwrap_or(0);
            let base = node.base_fee();
            Ok(json!({
                "baseFee": base.to_string(),
                "feeFloor": node.fee_floor().to_string(),
                "minFee": crate::types::MIN_FEE.to_string(),
                "targetTxsPerBlock": fees::TARGET_TXS_PER_BLOCK,
                "maxChangePct": fees::MAX_CHANGE_PCT,
                "maxBaseFee": fees::MAX_BASE_FEE.to_string(),
                "active": height + 1 >= FEE_MARKET_ACTIVATION_HEIGHT,
                "activationHeight": FEE_MARKET_ACTIVATION_HEIGHT,
                "mempool": node.mempool_size(),
            }))
        }
        // Light-client Merkle proof for one state leaf.
        "inaz_getProof" => {
            let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("acct");
            let key = params
                .get("key")
                .or_else(|| params.get("address"))
                .and_then(|v| v.as_str())
                .ok_or("key required")?;
            let (root, leaf_key, siblings, bitmap) = node.store.merkle_proof(domain, key);
            let value = node.store.merkle_leaf_value(domain, key);
            Ok(json!({
                "domain": domain,
                "key": key,
                "root": root,
                "leafKey": leaf_key,
                "value": value.as_ref().map(hex::encode),
                "exists": value.is_some(),
                "siblings": siblings,
                "siblingBitmap": bitmap,
                "depth": crate::smt::DEPTH,
                "activationHeight": crate::state::STATE_ROOT_V2_ACTIVATION_HEIGHT,
                "height": node.store.tip_height().unwrap_or(0),
                "finalizedHeight": node.store.finalized_height(),
            }))
        }
        // Stateless proof check, so bridges can sanity-check their own verifier.
        "inaz_verifyProof" => {
            let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("acct");
            let key = params.get("key").and_then(|v| v.as_str()).ok_or("key required")?;
            let root = params.get("root").and_then(|v| v.as_str()).ok_or("root required")?;
            let bitmap = params.get("siblingBitmap").and_then(|v| v.as_str()).unwrap_or("");
            let siblings: Vec<String> = params
                .get("siblings")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|s| s.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            let value = match params.get("value").and_then(|v| v.as_str()) {
                Some(h) if !h.is_empty() => Some(hex::decode(h).map_err(|_| "bad value hex")?),
                _ => None,
            };
            let ok = crate::smt::verify_proof(
                root,
                domain,
                key.as_bytes(),
                value.as_deref(),
                &siblings,
                bitmap,
            );
            Ok(json!({ "valid": ok }))
        }
        // State root of the merkleized state, with upgrade status.
        "inaz_stateRoot" => {
            let tip = node.store.tip_height().unwrap_or(0);
            Ok(json!({
                "height": tip,
                "stateRoot": node.store.state_root_at(tip),
                "merkleRoot": node.store.merkle_root(),
                "merkleReady": node.store.merkle_ready(),
                "activationHeight": crate::state::STATE_ROOT_V2_ACTIVATION_HEIGHT,
                "active": tip >= crate::state::STATE_ROOT_V2_ACTIVATION_HEIGHT,
                "depth": crate::smt::DEPTH,
            }))
        }
        "inaz_finalizedBlockNumber" => Ok(json!(node.store.finalized_height())),
        "inaz_finality" => {
            let tip = node.store.tip_height().unwrap_or(0);
            let height = params.get("height").and_then(|v| v.as_u64()).unwrap_or(tip);
            let (voted, total) = node.votes.tally(&node.store, height);
            let finalized = node.store.finalized_height();
            // Votes are pruned once a height is final; report it as fully voted.
            let is_final = height <= finalized;
            let voted = if is_final && voted == 0 { total } else { voted };
            Ok(json!({
                "height": height,
                "tipHeight": tip,
                "finalizedHeight": finalized,
                "isFinal": is_final,
                "votes": if is_final { node.validators().len() } else { node.votes.seen(height) },
                "votedStakeInaz": format_inaz(voted),
                "totalStakeInaz": format_inaz(total),
                "thresholdPct": 66.67,
                "votedPct": if total > 0 { (voted * 10_000 / total) as f64 / 100.0 } else { 0.0 },
                "validators": node.validators().len(),
                "peers": node.peer_count(),
            }))
        }
        "inaz_getBalance" | "inaz_getAccount" => {
            let addr = params
                .get("address")
                .and_then(|v| v.as_str())
                .ok_or("missing address")?;
            if !is_valid_address(addr) {
                return Err("invalid address".into());
            }
            let a = node.store.account(addr);
            Ok(json!({
                "address": addr,
                "balance": a.balance.to_string(),
                "balanceInaz": format_inaz(a.balance),
                "staked": a.staked.to_string(),
                "stakedInaz": format_inaz(a.staked),
                "unbonding": a.unbonding_total().to_string(),
                "unbondingInaz": format_inaz(a.unbonding_total()),
                "unbonds": a.unbonding.iter().map(|u| json!({
                    "amountInaz": format_inaz(u.amount),
                    "releaseHeight": u.release_height,
                })).collect::<Vec<_>>(),
                "rewardsInaz": format_inaz(a.rewards),
                "isValidator": a.is_validator(),
                "isJailed": a.is_jailed(node.store.tip_height().unwrap_or(0) + 1),
                "jailedUntil": a.penalties.jailed_until,
                "tombstoned": a.penalties.tombstoned,
                "slashedInaz": format_inaz(a.penalties.slashed),
                "missedSlots": a.penalties.missed_slots,
                "missedStreak": a.penalties.missed_streak,
                "downtimeJails": a.penalties.downtime_jails,
                "blocksProduced": a.blocks_produced,
                "nonce": a.nonce,
                "pendingNonce": node.pending_nonce(addr),
            }))
        }
        "inaz_validators" => {
            let set = node.validators();
            let total = staking::total_stake(&set);
            Ok(json!({
                "count": set.len(),
                "totalStakeInaz": format_inaz(total),
                "minStakeInaz": format_inaz(MIN_STAKE),
                "unbondingBlocks": UNBONDING_BLOCKS,
                "blockRewardInaz": format_inaz(staking::BLOCK_REWARD),
                "leaderCommissionPct": staking::LEADER_COMMISSION_PCT,
                "nextLeader": node.next_leader(),
                "validators": set.iter().map(|v| json!({
                    "address": v.address,
                    "stakeInaz": format_inaz(v.stake),
                    "sharePct": if total > 0 { (v.stake * 10_000 / total) as f64 / 100.0 } else { 0.0 },
                    "rewardsInaz": format_inaz(v.rewards),
                    "blocksProduced": v.blocks_produced,
                    "missedSlots": v.missed_slots,
                    "slashedInaz": format_inaz(v.slashed),
                    "jailed": false,
                })).collect::<Vec<_>>(),
                "jailed": staking::bonded_set(&node.store).iter()
                    .filter(|v| v.tombstoned || v.jailed_until > node.store.tip_height().unwrap_or(0) + 1)
                    .map(|v| json!({
                        "address": v.address,
                        "stakeInaz": format_inaz(v.stake),
                        "jailedUntil": v.jailed_until,
                        "tombstoned": v.tombstoned,
                        "missedSlots": v.missed_slots,
                        "slashedInaz": format_inaz(v.slashed),
                    })).collect::<Vec<_>>(),
            }))
        }
        // Slashing parameters, jail state and every punishment ever applied.
        "inaz_slashing" => {
            let height = node.store.tip_height().unwrap_or(0) + 1;
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(50).min(500) as usize;
            let records = node.store.slashes();
            let burned: u128 = records.iter().map(|r| r.burned).sum();
            Ok(json!({
                "height": height,
                "activationHeight": SLASHING_ACTIVATION_HEIGHT,
                "active": height >= SLASHING_ACTIVATION_HEIGHT,
                "params": {
                    "equivocationMinBurnPct": EQUIVOCATION_MIN_BURN_PCT,
                    "equivocationCorrelationFactor": EQUIVOCATION_CORRELATION_FACTOR,
                    "reporterBountyPct": REPORTER_BOUNTY_PCT,
                    "downtimeJailStreak": DOWNTIME_JAIL_STREAK,
                    "downtimeJailBlocks": DOWNTIME_JAIL_BLOCKS,
                    "downtimeRepeatBurnBps": DOWNTIME_REPEAT_BURN_BPS,
                    "evidenceMaxAgeBlocks": EVIDENCE_MAX_AGE_BLOCKS,
                    "unbondingBlocks": UNBONDING_BLOCKS,
                },
                "totalBurnedInaz": format_inaz(burned),
                "slashCount": records.len(),
                "slashes": records.iter().take(limit).map(|r| json!({
                    "id": r.id,
                    "offence": r.offence,
                    "offender": r.offender,
                    "offenceHeight": r.offence_height,
                    "appliedHeight": r.applied_height,
                    "burnedInaz": format_inaz(r.burned),
                    "bountyInaz": format_inaz(r.bounty),
                    "reporter": r.reporter,
                    "tombstoned": r.tombstoned,
                    "jailedUntil": if r.jailed_until == TOMBSTONE_HEIGHT { Value::Null } else { json!(r.jailed_until) },
                })).collect::<Vec<_>>(),
            }))
        }
        // Submit a proof directly over RPC. The node signs and pays the fee, and
        // keeps the reporter bounty.
        "inaz_reportEquivocation" => {
            let raw = params.get("evidence").cloned().ok_or("missing evidence")?;
            let evidence: Evidence =
                serde_json::from_value(raw).map_err(|e| format!("bad evidence: {}", e))?;
            let offender = evidence.verify()?;
            let hash = node.submit_report(&evidence)?;
            Ok(json!({ "hash": hash, "offender": offender, "offence": evidence.label() }))
        }
        // Preview what a proof would cost the offender, without submitting it.
        "inaz_previewSlash" => {
            let raw = params.get("evidence").cloned().ok_or("missing evidence")?;
            let evidence: Evidence =
                serde_json::from_value(raw).map_err(|e| format!("bad evidence: {}", e))?;
            let offender = evidence.verify()?;
            let acct = node.store.account(&offender);
            let total = node.store.total_staked();
            let pct = slashing::equivocation_burn_pct(acct.staked, total);
            let burn = acct.staked * pct / 100;
            Ok(json!({
                "offender": offender,
                "offence": evidence.label(),
                "offenceHeight": evidence.height(),
                "stakeInaz": format_inaz(acct.staked),
                "burnPct": pct,
                "burnInaz": format_inaz(burn),
                "bountyInaz": format_inaz(burn * REPORTER_BOUNTY_PCT / 100),
                "tombstone": true,
            }))
        }
        "inaz_getBlockByNumber" => {
            let h = params
                .get("height")
                .and_then(|v| v.as_u64())
                .or_else(|| node.store.tip_height())
                .ok_or("missing height")?;
            match node.store.block(h) {
                Some(b) => Ok(block_json(&b)),
                None => Ok(Value::Null),
            }
        }
        "inaz_latestBlocks" => {
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(10).min(100);
            let tip = node.store.tip_height().unwrap_or(0);
            let mut out = Vec::new();
            let mut h = tip as i64;
            while h >= 0 && out.len() < limit as usize {
                if let Some(b) = node.store.block(h as u64) {
                    out.push(block_json(&b));
                }
                h -= 1;
            }
            Ok(json!(out))
        }
        "inaz_getTransaction" => {
            let hash = params.get("hash").and_then(|v| v.as_str()).ok_or("missing hash")?;
            match node.store.tx_height(hash) {
                Some(h) => {
                    let block = node.store.block(h).ok_or("block missing")?;
                    let tx = block
                        .transactions
                        .iter()
                        .find(|t| t.hash() == hash)
                        .ok_or("tx missing in block")?;
                    let mut v = tx_json(tx);
                    v["blockHeight"] = json!(h);
                    v["blockHash"] = json!(block.hash);
                    v["status"] = json!("confirmed");
                    Ok(v)
                }
                None => Ok(Value::Null),
            }
        }
        "inaz_contracts" => {
            let list = node.store.contracts();
            Ok(json!({
                "count": list.len(),
                "deployFeeInaz": format_inaz(contracts::DEPLOY_FEE),
                "contracts": list.iter().map(contract_json).collect::<Vec<_>>(),
            }))
        }
        "inaz_getContract" => {
            let addr = params.get("address").and_then(|v| v.as_str()).ok_or("missing address")?;
            match node.store.contract(addr) {
                Some(c) => {
                    let mut v = contract_json(&c);
                    let acct = node.store.account(&c.address);
                    v["balanceInaz"] = json!(format_inaz(acct.balance));
                    v["storage"] = json!(node
                        .store
                        .contract_entries(&c.address, 50)
                        .into_iter()
                        .map(|(k, val)| json!({
                            "key": k,
                            "valueHex": hex::encode(&val),
                            "valueText": String::from_utf8_lossy(&val),
                        }))
                        .collect::<Vec<_>>());
                    Ok(v)
                }
                None => Ok(Value::Null),
            }
        }
        "inaz_contractStorage" => {
            let addr = params.get("address").and_then(|v| v.as_str()).ok_or("missing address")?;
            let key = params.get("key").and_then(|v| v.as_str()).ok_or("missing key")?;
            let val = node.store.contract_storage(addr, key);
            Ok(json!({
                "address": addr,
                "key": key,
                "found": val.is_some(),
                "valueHex": val.as_ref().map(hex::encode).unwrap_or_default(),
                "valueText": val.as_ref().map(|v| String::from_utf8_lossy(v).to_string()).unwrap_or_default(),
            }))
        }
        "inaz_getReceipt" => {
            let hash = params.get("hash").and_then(|v| v.as_str()).ok_or("missing hash")?;
            match node.store.receipt(hash) {
                Some(r) => Ok(json!({
                    "hash": hash,
                    "contract": r.contract,
                    "caller": r.caller,
                    "ok": r.ok,
                    "fuelUsed": r.fuel_used,
                    "height": r.height,
                    "returnHex": r.return_hex,
                    "returnText": hex::decode(&r.return_hex).map(|b| String::from_utf8_lossy(&b).to_string()).unwrap_or_default(),
                    "logs": r.logs,
                    "error": r.error,
                })),
                None => Ok(Value::Null),
            }
        }
        // Read-only contract call: runs the code, throws every state change away.
        "inaz_query" => {
            let addr = params.get("address").and_then(|v| v.as_str()).ok_or("missing address")?;
            let c = contracts::check_call(&node.store, addr)?;
            let code = node.store.code(&c.code_hash).ok_or("contract code missing")?;
            let args = params.get("args").and_then(|v| v.as_str()).unwrap_or("");
            let input = contracts::decode_args(&Some(Payload { args: args.to_string(), ..Default::default() }))?;
            let caller = params
                .get("caller")
                .and_then(|v| v.as_str())
                .unwrap_or(addr)
                .to_string();
            let height = node.store.tip_height().unwrap_or(0);
            let out = contracts::execute(
                &node.store,
                addr,
                &caller,
                &code,
                input,
                0,
                height,
                contracts::QUERY_FUEL,
            );
            Ok(json!({
                "address": addr,
                "ok": out.ok,
                "returnHex": hex::encode(&out.ret),
                "returnText": String::from_utf8_lossy(&out.ret),
                "logs": out.logs,
                "fuelUsed": out.fuel_used,
                "error": out.error,
                "writesDiscarded": out.writes.len(),
            }))
        }
        "inaz_sendTransaction" => {
            let raw = params.get("tx").cloned().unwrap_or_else(|| params.clone());
            let tx: Transaction = serde_json::from_value(raw).map_err(|e| format!("bad tx: {}", e))?;
            let predicted = match tx.kind {
                TxKind::DeployContract => {
                    let code = contracts::decode_code(&tx.payload)?;
                    tx.sender().map(|s| {
                        contracts::contract_address(&s, tx.nonce, &contracts::code_hash(&code))
                    })
                }
                _ => None,
            };
            let hash = node.accept_tx(tx.clone())?;
            node.gossip_tx(&tx);
            Ok(json!({ "hash": hash, "status": "pending", "contract": predicted }))
        }
        // Bulk submit — one HTTP round trip for many txs. Used by load tests and
        // by wallets that batch. Rejections are reported per index, not fatal.
        "inaz_sendTransactions" => {
            let list = params
                .get("txs")
                .and_then(|v| v.as_array())
                .cloned()
                .ok_or("missing txs array")?;
            if list.len() > MAX_BATCH_TXS {
                return Err(format!("batch too large (max {})", MAX_BATCH_TXS));
            }
            // Decode first, then hand every well-formed transaction to the node in
            // one call: signatures are verified in parallel and the mempool lock is
            // taken once for the batch instead of once per transaction.
            let mut errors: Vec<Value> = Vec::new();
            let mut txs: Vec<Transaction> = Vec::with_capacity(list.len());
            let mut indices: Vec<usize> = Vec::with_capacity(list.len());
            for (i, raw) in list.into_iter().enumerate() {
                match serde_json::from_value::<Transaction>(raw) {
                    Ok(tx) => {
                        txs.push(tx);
                        indices.push(i);
                    }
                    Err(e) => {
                        if errors.len() < 20 {
                            errors.push(json!({ "index": i, "error": format!("bad tx: {}", e) }));
                        }
                    }
                }
            }
            let mut rejected = errors.len();
            let results = node.accept_batch(txs.clone());
            let mut accepted = 0usize;
            let mut hashes: Vec<String> = Vec::new();
            for ((idx, tx), res) in indices.into_iter().zip(txs.iter()).zip(results) {
                match res {
                    Ok(hash) => {
                        accepted += 1;
                        if hashes.len() < 1_000 {
                            hashes.push(hash);
                        }
                        node.gossip_tx(tx);
                    }
                    Err(e) => {
                        rejected += 1;
                        if errors.len() < 20 {
                            errors.push(json!({ "index": idx, "error": e }));
                        }
                    }
                }
            }
            Ok(json!({
                "accepted": accepted,
                "rejected": rejected,
                "errors": errors,
                "hashes": hashes,
                "mempool": node.mempool_size(),
            }))
        }
        // Preflight: run every admission and execution check against live state
        // and report the verdict without writing anything. A client can fix a bad
        // nonce or a short balance before it ever pays for a failed submission.
        "inaz_simulateTransaction" => {
            let raw = params.get("tx").cloned().unwrap_or_else(|| params.clone());
            let tx: Transaction = serde_json::from_value(raw).map_err(|e| format!("bad tx: {}", e))?;
            Ok(crate::simulate::preflight(node, &tx))
        }
        // Batch status lookup: where each transaction is right now, in one call.
        "inaz_signatureStatuses" => {
            let hashes = params
                .get("hashes")
                .and_then(|v| v.as_array())
                .cloned()
                .ok_or("missing hashes array")?;
            if hashes.len() > 256 {
                return Err("too many hashes (max 256)".into());
            }
            let finalized = node.store.finalized_height();
            let pool = node.mempool.lock().unwrap();
            let out: Vec<Value> = hashes
                .iter()
                .map(|h| {
                    let hash = h.as_str().unwrap_or("").to_lowercase();
                    match node.store.tx_height(&hash) {
                        Some(height) => json!({
                            "hash": hash,
                            "status": if height <= finalized { "finalized" } else { "confirmed" },
                            "height": height,
                            "confirmations": node.store.tip_height().unwrap_or(0).saturating_sub(height) + 1,
                        }),
                        None if pool.contains(&hash) => {
                            json!({ "hash": hash, "status": "pending" })
                        }
                        None => json!({ "hash": hash, "status": "unknown" }),
                    }
                })
                .collect();
            Ok(json!({ "statuses": out, "finalizedHeight": finalized }))
        }
        // Fee guidance from the live pool, so a client does not have to guess what
        // "fast" costs right now.
        "inaz_priorityFee" => {
            let base = node.store.base_fee();
            let floor = node.fee_floor();
            let pool = node.mempool.lock().unwrap();
            let mut fees = pool.fees();
            drop(pool);
            fees.sort_unstable();
            let pct = |p: usize| -> u128 {
                if fees.is_empty() {
                    return floor;
                }
                let idx = (fees.len().saturating_sub(1)) * p / 100;
                fees[idx].max(floor)
            };
            Ok(json!({
                "baseFee": base.to_string(),
                "floor": floor.to_string(),
                "queued": fees.len(),
                "slow": floor.to_string(),
                "normal": pct(50).to_string(),
                "fast": pct(90).to_string(),
                "urgent": (pct(90).saturating_mul(2)).to_string(),
            }))
        }
        // Serving health: how far behind the tip this endpoint is. A read replica
        // reports its own lag so a client can route away from a stale node.
        "inaz_nodeStatus" => {
            let tip = node.store.tip_height().unwrap_or(0);
            Ok(json!({
                "role": if node.serving_only() { "replica" } else { "validator" },
                "height": tip,
                "finalizedHeight": node.store.finalized_height(),
                "peers": node.peer_count(),
                "mempool": node.mempool_size(),
                "liveSubscriptions": node.events.len(),
                "chainId": node.genesis.chain_id,
                "syncing": node.peer_count() > 0 && node.behind_tip(),
            }))
        }
        _ => Err(format!("unknown method {}", method)),
    }
}

/// `inaz_rpcLimits` reports the caller's own weighting; the credential is passed
/// through params only when a caller asks about a specific key it already holds.
fn credential_hint(params: &Value) -> Option<&str> {
    params.get("key").and_then(|v| v.as_str())
}
