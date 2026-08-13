//! Inazuma consensus + execution: mempool, transaction application, block production.

use crate::crypto::{is_valid_address, Keypair};
use crate::consensus::VoteTracker;
use crate::contracts::{self, DEPLOY_FEE};
use crate::events::{Event, EventBus};
use crate::fees::{self, FEE_MARKET_ACTIVATION_HEIGHT};
use crate::mempool::{Mempool, MAX_PENDING_PER_SENDER};
use crate::state::Store;
use crate::staking::{self, Validator};
use crate::slashing::{self, Evidence};
use crate::tokens::{self, TOKEN_CREATION_FEE};
use crate::types::{
    txs_root, Block, Genesis, Transaction, TxKind, Unbond, MIN_FEE, MIN_STAKE, UNBONDING_BLOCKS,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Signature verification is the dominant cost of both admission and block
/// import, and it is perfectly parallel, so it is spread across the cores the
/// machine actually has (a 2 vCPU validator gets 2, a 4 vCPU one gets 4).
const VERIFY_PARALLEL_THRESHOLD: usize = 64;

pub fn verify_threads() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2).clamp(1, 16)
}

pub const MAX_TXS_PER_BLOCK: usize = 5_000;
/// How many slots a leader may miss before the next deterministic candidate
/// is allowed to seal that height.
/// Absolute ceiling on rotation attempts accepted for one height. Large enough
/// that a long outage still heals, small enough to bound validation work.
pub const MAX_LEADER_ATTEMPTS: u64 = 4096;
/// Extra attempts tolerated on import to absorb clock and network jitter.
pub const LEADER_ATTEMPT_SLACK: u64 = 2;

pub fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u128
}

/// Stateless part of admission: cheap rejects first, then the one expensive
/// signature check, then sender recovery and hashing. No locks are involved, so
/// this can run on any thread while the node keeps producing blocks.
fn precheck_tx(
    tx: Transaction,
    chain_id: u64,
) -> Result<(Transaction, String, String), String> {
    if tx.chain_id != chain_id {
        return Err("wrong chain id".into());
    }
    if tx.fee < MIN_FEE {
        return Err(format!("fee below minimum ({} rai)", MIN_FEE));
    }
    if !tx.verify_signature() {
        return Err("invalid signature".into());
    }
    let sender = tx.sender().ok_or("invalid sender public key")?;
    let hash = tx.hash();
    Ok((tx, hash, sender))
}

/// Verify every transaction signature in a block, spreading the work across
/// threads for large blocks. Returns false if any signature fails.
pub fn verify_signatures(txs: &[Transaction]) -> bool {
    if txs.len() < VERIFY_PARALLEL_THRESHOLD {
        return txs.iter().all(|t| t.verify_signature());
    }
    let chunk = txs.len().div_ceil(verify_threads());
    std::thread::scope(|scope| {
        let handles: Vec<_> = txs
            .chunks(chunk)
            .map(|part| scope.spawn(move || part.iter().all(|t| t.verify_signature())))
            .collect();
        handles.into_iter().all(|h| h.join().unwrap_or(false))
    })
}

pub struct Node {
    pub store: Store,
    pub genesis: Genesis,
    pub producer: Keypair,
    pub mempool: Mutex<Mempool>,
    /// Held while a block executes, so admission never sees a half-applied block.
    exec_lock: Mutex<()>,
    /// Single-node mode: seal every slot even when another validator is elected.
    /// Turned off automatically once the node has peers to gossip with.
    solo: AtomicBool,
    /// Finality precommits seen from the validator set.
    pub votes: VoteTracker,
    /// Wall-clock ms when the current tip was adopted, used for slot fallback.
    tip_seen_ms: AtomicU64,
    /// Peer set used to gossip transactions accepted over RPC. Set once at boot.
    gossip: Mutex<Option<std::sync::Arc<crate::p2p::P2p>>>,
    /// Live push subscriptions. Publishing never blocks consensus.
    pub events: EventBus,
    /// Finalized height already announced, so finality fires once per height.
    announced_final: AtomicU64,
    /// Serving-only (read replica): syncs and answers queries, never seals a
    /// block and never votes. Adding replicas scales reads without touching the
    /// validator set, so read traffic cannot crowd out consensus.
    serving_only: AtomicBool,
}

impl Node {
    pub fn new(store: Store, genesis: Genesis, producer: Keypair) -> Self {
        Node {
            store,
            genesis,
            producer,
            mempool: Mutex::new(Mempool::new()),
            exec_lock: Mutex::new(()),
            solo: AtomicBool::new(true),
            votes: VoteTracker::new(),
            tip_seen_ms: AtomicU64::new(now_ms() as u64),
            gossip: Mutex::new(None),
            events: EventBus::new(),
            announced_final: AtomicU64::new(0),
            serving_only: AtomicBool::new(false),
        }
    }

    pub fn gossip_handle(&self) -> Option<std::sync::Arc<crate::p2p::P2p>> {
        self.gossip.lock().unwrap().clone()
    }

    pub fn attach_gossip(&self, p2p: std::sync::Arc<crate::p2p::P2p>) {
        *self.gossip.lock().unwrap() = Some(p2p);
    }

    /// Forward a locally accepted transaction to peers so any leader can include it.
    pub fn gossip_tx(&self, tx: &Transaction) {
        let peers = self.gossip.lock().unwrap().clone();
        if let Some(p2p) = peers {
            crate::p2p::announce_tx(&p2p, tx);
        }
    }

    pub fn set_serving_only(&self, on: bool) {
        self.serving_only.store(on, Ordering::Relaxed);
    }

    pub fn serving_only(&self) -> bool {
        self.serving_only.load(Ordering::Relaxed)
    }

    /// True when the tip has not moved for several slots while peers are present,
    /// i.e. this endpoint is probably serving stale reads.
    pub fn behind_tip(&self) -> bool {
        let slot = self.genesis.block_time_ms.max(1) as u128;
        let seen = self.tip_seen_ms.load(Ordering::Relaxed) as u128;
        now_ms().saturating_sub(seen) > slot * 6
    }

    pub fn peer_count(&self) -> usize {
        self.gossip
            .lock()
            .unwrap()
            .as_ref()
            .map(|p| p.peers.len())
            .unwrap_or(0)
    }

    pub fn set_solo(&self, solo: bool) {
        self.solo.store(solo, Ordering::Relaxed);
    }

    pub fn solo(&self) -> bool {
        self.solo.load(Ordering::Relaxed)
    }

    /// True when this node's own key has enough stake to validate and vote.
    pub fn is_bonded_validator(&self) -> bool {
        self.store.account(&self.producer.address()).staked >= MIN_STAKE
    }

    /// Slot attempt for the next height. Derived from the parent block's own
    /// timestamp, not local state, so every node reaches the same answer and the
    /// primary leader always gets a full grace slot before anyone takes over.
    fn current_attempt(&self) -> u64 {
        let parent_ts = self
            .store
            .tip_height()
            .and_then(|h| self.store.block(h))
            .map(|b| b.timestamp_ms)
            .unwrap_or(0);
        if parent_ts == 0 {
            let seen = self.tip_seen_ms.load(Ordering::Relaxed) as u128;
            let elapsed = now_ms().saturating_sub(seen) as u64;
            return (elapsed / self.genesis.block_time_ms.max(1)).min(MAX_LEADER_ATTEMPTS);
        }
        let elapsed = now_ms().saturating_sub(parent_ts) as u64;
        let slot = self.genesis.block_time_ms.max(1);
        // One slot for the primary leader, one grace slot, then rotate forever.
        // The rotation must never stop: if it were capped, a chain whose capped
        // leader is offline would halt permanently instead of failing over.
        (elapsed / slot).saturating_sub(1)
    }

    fn mark_tip_seen(&self) {
        self.tip_seen_ms.store(now_ms() as u64, Ordering::Relaxed);
    }

    /// Write genesis allocations and seal block 0.
    pub fn init_genesis(&self) -> Result<Block, String> {
        if self.store.is_initialized() {
            return Err("chain already initialized".into());
        }
        for a in &self.genesis.alloc {
            if !is_valid_address(&a.address) {
                return Err(format!("invalid genesis address {}", a.address));
            }
            let mut acct = self.store.account(&a.address);
            acct.balance += crate::types::parse_inaz(&a.balance)?;
            if let Some(stake) = &a.stake {
                acct.staked += crate::types::parse_inaz(stake)?;
            }
            self.store.set_account(&a.address, &acct);
        }
        self.store.flush_stakers();
        // Genesis must be byte-identical on every node, so it carries no
        // node-specific producer, timestamp or signature.
        let mut block = Block {
            height: 0,
            parent_hash: "0".repeat(64),
            timestamp_ms: 0,
            state_root: self.store.state_root(),
            txs_root: txs_root(&[]),
            producer: "genesis".to_string(),
            producer_pubkey: String::new(),
            transactions: Vec::new(),
            signature: String::new(),
            hash: String::new(),
        };
        block.hash = block.compute_hash();
        self.store.put_block(&block);
        Ok(block)
    }

    /// Stateless + state checks before a transaction enters the mempool.
    pub fn accept_tx(&self, tx: Transaction) -> Result<String, String> {
        self.accept_batch(vec![tx])
            .pop()
            .unwrap_or_else(|| Err("empty batch".into()))
    }

    /// Admit many transactions with a single pass over the locks.
    ///
    /// Everything that does not touch state — chain id, fee floor, signature,
    /// sender recovery, hashing — happens first and in parallel. Only then is the
    /// execution lock taken, once for the whole batch, and the mempool lock taken
    /// once inside it. Per-transaction locking was the throughput ceiling: a
    /// 500-transaction submission used to acquire and release both locks 500
    /// times while block production waited its turn between each one.
    ///
    /// Results are returned positionally, so a caller can report per-transaction
    /// outcomes even though admission was batched.
    pub fn accept_batch(&self, txs: Vec<Transaction>) -> Vec<Result<String, String>> {
        if txs.is_empty() {
            return Vec::new();
        }
        let mut prepared = self.precheck_batch(txs);

        let _exec = self.exec_lock.lock().unwrap();
        let next_height = self.store.tip_height().unwrap_or(0) + 1;
        let floor = fees::required_fee(next_height, self.store.base_fee());
        let mut pool = self.mempool.lock().unwrap();
        prepared
            .drain(..)
            .map(|item| match item {
                Err(e) => Err(e),
                Ok((tx, hash, sender)) => self.admit(&mut pool, tx, hash, sender, floor),
            })
            .collect()
    }

    /// Stateless admission checks, spread over threads for large batches.
    fn precheck_batch(
        &self,
        txs: Vec<Transaction>,
    ) -> Vec<Result<(Transaction, String, String), String>> {
        let chain_id = self.genesis.chain_id;
        if txs.len() < VERIFY_PARALLEL_THRESHOLD {
            return txs.into_iter().map(|tx| precheck_tx(tx, chain_id)).collect();
        }
        let chunk = txs.len().div_ceil(verify_threads());
        let chunks: Vec<Vec<Transaction>> = txs
            .chunks(chunk)
            .map(|c| c.to_vec())
            .collect();
        std::thread::scope(|scope| {
            let handles: Vec<_> = chunks
                .into_iter()
                .map(|part| {
                    scope.spawn(move || {
                        part.into_iter()
                            .map(|tx| precheck_tx(tx, chain_id))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().unwrap_or_default())
                .collect()
        })
    }

    /// State-dependent admission for one transaction. Both the execution lock and
    /// the mempool lock are already held by the caller.
    fn admit(
        &self,
        pool: &mut Mempool,
        tx: Transaction,
        hash: String,
        sender: String,
        floor: u128,
    ) -> Result<String, String> {
        if tx.fee < floor {
            return Err(format!("fee below current base fee ({} rai)", floor));
        }
        match tx.kind {
            TxKind::Transfer => {
                if !is_valid_address(&tx.to) {
                    return Err("invalid recipient address".into());
                }
            }
            TxKind::Stake => {
                if tx.amount == 0 {
                    return Err("stake amount must be positive".into());
                }
            }
            TxKind::Unstake => {
                if tx.amount == 0 {
                    return Err("unstake amount must be positive".into());
                }
                if self.store.account(&sender).staked < tx.amount {
                    return Err("not enough staked".into());
                }
            }
            TxKind::ReportEquivocation => {
                let height = self.store.tip_height().unwrap_or(0) + 1;
                slashing::check_report(&self.store, height, &tx.payload)?;
            }
            TxKind::Unjail => {
                let acct = self.store.account(&sender);
                let height = self.store.tip_height().unwrap_or(0) + 1;
                if acct.penalties.tombstoned {
                    return Err("tombstoned validators can never rejoin".into());
                }
                if acct.penalties.jailed_until == 0 {
                    return Err("validator is not jailed".into());
                }
                if acct.penalties.jailed_until > height {
                    return Err("jail period has not expired yet".into());
                }
            }
            TxKind::CreateToken => {
                tokens::check_create(&self.store, &sender, tx.nonce, &tx.payload)?;
            }
            TxKind::MintToken => {
                tokens::check_mint(&self.store, &sender, &tx.to, tx.amount, &tx.payload)?;
            }
            TxKind::TokenTransfer => {
                tokens::check_token_transfer(&self.store, &sender, &tx.to, tx.amount, &tx.payload)?;
            }
            TxKind::BurnToken => {
                tokens::check_burn(&self.store, &sender, tx.amount, &tx.payload)?;
            }
            TxKind::DeployContract => {
                let code = contracts::decode_code(&tx.payload)?;
                contracts::check_deploy(&code)?;
            }
            TxKind::CallContract => {
                contracts::check_call(&self.store, &tx.to)?;
                contracts::decode_args(&tx.payload)?;
            }
        }
        let acct = self.store.account(&sender);
        let pending = pool.pending_for(&sender);
        if tx.nonce != acct.nonce + pending {
            return Err(format!("bad nonce: expected {}", acct.nonce + pending));
        }
        // Unstake moves coins out of `staked`, so only the fee comes from the
        // balance. Token transactions move token units, never INAZ, except the
        // one-off creation fee.
        let required = match tx.kind {
            TxKind::Unstake => tx.fee,
            TxKind::ReportEquivocation | TxKind::Unjail => tx.fee,
            TxKind::CreateToken => tx.fee + TOKEN_CREATION_FEE,
            TxKind::MintToken | TxKind::TokenTransfer | TxKind::BurnToken => tx.fee,
            TxKind::DeployContract => tx.fee + DEPLOY_FEE + tx.amount,
            _ => tx.amount + tx.fee,
        };
        if acct.balance < required {
            return Err("insufficient balance".into());
        }
        if pending >= MAX_PENDING_PER_SENDER {
            return Err(format!(
                "too many queued transactions for this account (max {})",
                MAX_PENDING_PER_SENDER
            ));
        }
        if self.store.tx_height(&hash).is_some() || pool.contains(&hash) {
            return Err("duplicate transaction".into());
        }
        // Priority lane. A full pool is a market, not a wall: the cheapest queued
        // transaction makes way for one that pays more, and only a transaction
        // that pays less than everything already queued is turned away. Without
        // this, a flood of floor-fee spam could lock out paying users for free.
        if pool.is_full() && pool.evict_cheapest_below(tx.fee).is_none() {
            return Err("mempool full: raise the fee to take priority".into());
        }
        let fee = tx.fee;
        let kind = tx.kind.label();
        pool.insert(tx, hash.clone(), sender.clone());
        self.events.publish(Event::new(
            "mempool",
            None,
            serde_json::json!({
                "hash": hash, "from": sender, "kind": kind,
                "fee": fee.to_string(), "poolSize": pool.len(),
            }),
        ));
        Ok(hash)
    }

    fn apply_tx(&self, tx: &Transaction, height: u64) -> Result<u128, String> {
        let sender = tx.sender().ok_or("bad sender")?;
        // Token rules are re-checked against live state before anything is
        // written, so a failed token tx can never leave a partial state change.
        match tx.kind {
            TxKind::CreateToken => tokens::check_create(&self.store, &sender, tx.nonce, &tx.payload)?,
            TxKind::MintToken => tokens::check_mint(&self.store, &sender, &tx.to, tx.amount, &tx.payload)?,
            TxKind::TokenTransfer => {
                tokens::check_token_transfer(&self.store, &sender, &tx.to, tx.amount, &tx.payload)?
            }
            TxKind::BurnToken => tokens::check_burn(&self.store, &sender, tx.amount, &tx.payload)?,
            TxKind::DeployContract => {
                let code = contracts::decode_code(&tx.payload)?;
                contracts::check_deploy(&code)?;
            }
            TxKind::CallContract => {
                contracts::check_call(&self.store, &tx.to)?;
                contracts::decode_args(&tx.payload)?;
            }
            _ => {}
        }
        let mut from = self.store.account(&sender);
        if tx.nonce != from.nonce {
            return Err("stale nonce".into());
        }
        let debit = match tx.kind {
            TxKind::Unstake => tx.fee,
            TxKind::ReportEquivocation | TxKind::Unjail => tx.fee,
            TxKind::CreateToken => tx.fee + TOKEN_CREATION_FEE,
            TxKind::MintToken | TxKind::TokenTransfer | TxKind::BurnToken => tx.fee,
            TxKind::DeployContract => tx.fee + DEPLOY_FEE + tx.amount,
            _ => tx.amount + tx.fee,
        };
        if from.balance < debit {
            return Err("insufficient balance".into());
        }
        from.balance -= debit;
        from.nonce += 1;

        match tx.kind {
            TxKind::Transfer => {
                if tx.to == sender {
                    from.balance += tx.amount;
                    self.store.set_account(&sender, &from);
                } else {
                    self.store.set_account(&sender, &from);
                    let mut to = self.store.account(&tx.to);
                    to.balance += tx.amount;
                    self.store.set_account(&tx.to, &to);
                }
            }
            TxKind::Stake => {
                from.staked += tx.amount;
                self.store.set_account(&sender, &from);
            }
            TxKind::ReportEquivocation => {
                self.store.set_account(&sender, &from);
                let evidence = slashing::check_report(&self.store, height, &tx.payload)?;
                slashing::apply_report(&self.store, height, &sender, &evidence)?;
            }
            TxKind::Unjail => {
                self.store.set_account(&sender, &from);
                slashing::apply_unjail(&self.store, height, &sender)?;
            }
            TxKind::Unstake => {
                if from.staked < tx.amount {
                    return Err("not enough staked".into());
                }
                from.staked -= tx.amount;
                // Locked until the unbonding period passes, then credited automatically.
                from.unbonding.push(Unbond {
                    amount: tx.amount,
                    release_height: height + UNBONDING_BLOCKS,
                });
                self.store.set_account(&sender, &from);
            }
            TxKind::CreateToken => {
                self.store.set_account(&sender, &from);
                tokens::apply_create(&self.store, &sender, tx.nonce, tx.amount, height, &tx.payload)?;
            }
            TxKind::MintToken => {
                self.store.set_account(&sender, &from);
                tokens::apply_mint(&self.store, &sender, &tx.to, tx.amount, &tx.payload)?;
            }
            TxKind::TokenTransfer => {
                self.store.set_account(&sender, &from);
                tokens::apply_token_transfer(&self.store, &sender, &tx.to, tx.amount, &tx.payload)?;
            }
            TxKind::BurnToken => {
                self.store.set_account(&sender, &from);
                tokens::apply_burn(&self.store, &sender, tx.amount, &tx.payload)?;
            }
            TxKind::DeployContract => {
                self.store.set_account(&sender, &from);
                let code = contracts::decode_code(&tx.payload)?;
                let hash = contracts::code_hash(&code);
                let address = contracts::contract_address(&sender, tx.nonce, &hash);
                if self.store.contract(&address).is_some() {
                    return Err("contract already exists".into());
                }
                self.store.put_code(&hash, &code);
                self.store.set_contract(&contracts::Contract {
                    address: address.clone(),
                    code_hash: hash,
                    code_size: code.len(),
                    creator: sender.clone(),
                    created_height: height,
                    calls: 0,
                });
                // Any INAZ sent with the deploy funds the contract account.
                if tx.amount > 0 {
                    let mut c = self.store.account(&address);
                    c.balance += tx.amount;
                    self.store.set_account(&address, &c);
                }
                println!("[vm] deployed {} by {}", address, sender);
            }
            TxKind::CallContract => {
                self.store.set_account(&sender, &from);
                let c = contracts::check_call(&self.store, &tx.to)?;
                let code = self.store.code(&c.code_hash).ok_or("contract code missing")?;
                let input = contracts::decode_args(&tx.payload)?;
                // Attached value lands on the contract before it runs, so the
                // contract can spend or refund it during the call.
                if tx.amount > 0 {
                    let mut acct = self.store.account(&tx.to);
                    acct.balance += tx.amount;
                    self.store.set_account(&tx.to, &acct);
                }
                let outcome = contracts::execute(
                    &self.store,
                    &tx.to,
                    &sender,
                    &code,
                    input,
                    tx.amount,
                    height,
                    contracts::fuel_for_fee(tx.fee),
                );
                let receipt = outcome.receipt(&tx.to, &sender, height);
                self.store.put_receipt(&tx.hash(), &receipt);
                if !outcome.ok {
                    // Revert: hand the attached value back, keep the fee.
                    if tx.amount > 0 {
                        let mut acct = self.store.account(&tx.to);
                        acct.balance = acct.balance.saturating_sub(tx.amount);
                        self.store.set_account(&tx.to, &acct);
                        let mut back = self.store.account(&sender);
                        back.balance += tx.amount;
                        self.store.set_account(&sender, &back);
                    }
                    let mut updated = c.clone();
                    updated.calls += 1;
                    self.store.set_contract(&updated);
                    println!(
                        "[vm] call {} reverted: {}",
                        tx.to,
                        receipt.error.clone().unwrap_or_default()
                    );
                } else {
                    for (key, value) in &outcome.writes {
                        self.store.set_contract_storage(&tx.to, key, value.as_deref());
                    }
                    for (to, amount) in &outcome.transfers {
                        let mut cacct = self.store.account(&tx.to);
                        if cacct.balance < *amount {
                            return Err("contract overspent".into());
                        }
                        cacct.balance -= *amount;
                        self.store.set_account(&tx.to, &cacct);
                        let mut dest = self.store.account(to);
                        dest.balance += *amount;
                        self.store.set_account(to, &dest);
                    }
                    let mut updated = c.clone();
                    updated.calls += 1;
                    self.store.set_contract(&updated);
                }
            }
        }
        // The creation fee joins the block's fee pool, so it is paid out to the
        // validator set rather than vanishing.
        let collected = match tx.kind {
            TxKind::CreateToken => tx.fee + TOKEN_CREATION_FEE,
            TxKind::DeployContract => tx.fee + DEPLOY_FEE,
            _ => tx.fee,
        };
        Ok(collected)
    }

    /// Active validator set: accounts staking at least the minimum.
    pub fn validators(&self) -> Vec<Validator> {
        staking::validator_set(&self.store)
    }

    /// Who is scheduled to seal the next block.
    pub fn next_leader(&self) -> Option<String> {
        let height = self.store.tip_height().unwrap_or(0) + 1;
        staking::elect_leader_attempt(
            &self.validators(),
            height,
            &self.store.tip_hash(),
            self.current_attempt(),
        )
    }

    /// Seal the next block if this node is the elected leader: drain the mempool,
    /// execute, release matured unbonds, pay the validator set, store the block.
    /// `Ok(None)` means the slot belongs to another validator.
    pub fn produce_block(&self) -> Result<Option<Block>, String> {
        // A replica never produces, whatever the schedule says.
        if self.serving_only() {
            return Ok(None);
        }
        let _exec = self.exec_lock.lock().unwrap();
        let parent_height = self.store.tip_height().ok_or("chain not initialized")?;
        let parent_hash = self.store.tip_hash();
        let height = parent_height + 1;

        let set = staking::validator_set(&self.store);
        let attempt = self.current_attempt();
        let elected = staking::elect_leader_attempt(&set, height, &parent_hash, attempt);
        let producer_addr = self.producer.address();
        if let Some(leader) = &elected {
            if leader != &producer_addr && !self.solo() {
                return Ok(None);
            }
        }
        if set.is_empty() && !self.solo() {
            // No stake bonded yet and we are networked: wait rather than fork.
            return Ok(None);
        }

        let batch: Vec<Transaction> = {
            let mut pool = self.mempool.lock().unwrap();
            pool.take_batch(MAX_TXS_PER_BLOCK)
        };

        let mut included: Vec<Transaction> = Vec::with_capacity(batch.len());
        let mut fees: u128 = 0;
        for tx in batch {
            match self.apply_tx(&tx, height) {
                Ok(fee) => {
                    fees += fee;
                    included.push(tx);
                }
                Err(_) => { /* invalid at execution time: dropped */ }
            }
        }

        staking::release_unbonded(&self.store, height);
        // Liveness is charged before rewards, so a validator jailed this height
        // is already out of the set that gets paid.
        slashing::record_liveness(&self.store, height, &parent_hash, &producer_addr);
        staking::pay_rewards(&self.store, &producer_addr, fees);

        let mut block = Block {
            height,
            parent_hash,
            timestamp_ms: now_ms(),
            state_root: self.store.state_root_at(height),
            txs_root: txs_root(&included),
            producer: producer_addr,
            producer_pubkey: self.producer.pubkey_hex(),
            transactions: included,
            signature: String::new(),
            hash: String::new(),
        };
        block.signature = self.producer.sign_hex(&block.header_bytes());
        block.hash = block.compute_hash();
        self.store.put_block(&block);
        self.store
            .set_base_fee(fees::next_base_fee(self.store.base_fee(), block.transactions.len()));
        self.store.flush_stakers();
        self.store.flush_state_tree();
        self.store.flush_tokens();
        self.store.flush_contracts();
        self.mark_tip_seen();
        if let Some(h) = self.votes.replay_pending(&self.store, block.height) {
            println!("[final] height {} finalized", h);
        }
        self.publish_block(&block);
        Ok(Some(block))
    }

    /// Validate and apply a block received from a peer. `Ok(false)` means the
    /// block is one we already have; `Err` means it was rejected.
    pub fn import_block(&self, block: &Block) -> Result<bool, String> {
        let _exec = self.exec_lock.lock().unwrap();
        let tip = self.store.tip_height().ok_or("chain not initialized")?;
        if block.height <= tip {
            return Ok(false);
        }
        if block.height != tip + 1 {
            return Err(format!("out of order: have {}, got {}", tip, block.height));
        }
        if block.parent_hash != self.store.tip_hash() {
            return Err("parent hash mismatch".into());
        }
        if !block.verify_producer() {
            return Err("bad producer signature".into());
        }
        if block.transactions.len() > MAX_TXS_PER_BLOCK {
            return Err("too many transactions".into());
        }
        if txs_root(&block.transactions) != block.txs_root {
            return Err("txs root mismatch".into());
        }

        // The producer must be a leader this height could legitimately elect.
        // The attempt window comes from the block's own timestamp versus its
        // parent's, so replaying old history is judged the same way the network
        // judged it live — never against the importer's wall clock.
        let set = staking::validator_set(&self.store);
        if !set.is_empty() {
            let parent_ts = self.store.block(tip).map(|b| b.timestamp_ms).unwrap_or(0);
            let slot = self.genesis.block_time_ms.max(1);
            let elapsed = block.timestamp_ms.saturating_sub(parent_ts) as u64;
            let max_attempt = (elapsed / slot)
                .saturating_add(LEADER_ATTEMPT_SLACK)
                .min(MAX_LEADER_ATTEMPTS);
            let allowed = (0..=max_attempt).any(|a| {
                staking::elect_leader_attempt(&set, block.height, &block.parent_hash, a).as_deref()
                    == Some(block.producer.as_str())
            });
            if !allowed {
                return Err("producer is not an elected leader for this height".into());
            }
        }

        let floor = fees::required_fee(block.height, self.store.base_fee());
        for tx in &block.transactions {
            if tx.chain_id != self.genesis.chain_id {
                return Err("transaction from another chain".into());
            }
            if tx.fee < MIN_FEE {
                return Err("transaction fee below minimum".into());
            }
            if block.height >= FEE_MARKET_ACTIVATION_HEIGHT && tx.fee < floor {
                return Err("transaction fee below block base fee".into());
            }
        }
        if !verify_signatures(&block.transactions) {
            return Err("invalid transaction signature".into());
        }

        let mut fees: u128 = 0;
        for tx in &block.transactions {
            let fee = self
                .apply_tx(tx, block.height)
                .map_err(|e| format!("tx {} invalid: {}", &tx.hash()[..8], e))?;
            fees += fee;
        }
        staking::release_unbonded(&self.store, block.height);
        slashing::record_liveness(
            &self.store,
            block.height,
            &block.parent_hash,
            &block.producer,
        );
        staking::pay_rewards(&self.store, &block.producer, fees);

        let local_root = self.store.state_root_at(block.height);
        if local_root != block.state_root {
            return Err(format!(
                "state root mismatch at #{}: local {} peer {}",
                block.height, local_root, block.state_root
            ));
        }

        let mut stored = block.clone();
        stored.hash = block.hash.clone();
        self.store.put_block(&stored);
        self.store
            .set_base_fee(fees::next_base_fee(self.store.base_fee(), block.transactions.len()));
        self.store.flush_stakers();
        self.store.flush_state_tree();
        self.store.flush_tokens();
        self.store.flush_contracts();
        self.mark_tip_seen();
        if let Some(h) = self.votes.replay_pending(&self.store, block.height) {
            println!("[final] height {} finalized", h);
        }

        // Drop anything the block already confirmed from our mempool.
        let included: std::collections::HashSet<String> =
            block.transactions.iter().map(|t| t.hash()).collect();
        self.mempool.lock().unwrap().remove_hashes(&included);
        self.publish_block(&stored);
        Ok(true)
    }

    /// Wipe local state back to genesis so the node can replay a peer's chain.
    /// Refused if it would discard a height this node already finalized.
    pub fn reset_to_genesis(&self, peer_height: u64) -> Result<(), String> {
        let _exec = self.exec_lock.lock().unwrap();
        let finalized = self.store.finalized_height();
        if peer_height < finalized {
            return Err(format!(
                "refusing reorg below finalized height {} (peer at {})",
                finalized, peer_height
            ));
        }
        self.store.reset_chain();
        self.mempool.lock().unwrap().clear();
        drop(_exec);
        self.init_genesis()?;
        self.mark_tip_seen();
        Ok(())
    }

    /// Push a sealed block to every live subscription: the header, each
    /// transaction's outcome, each touched account's new balance, contract
    /// activity, and finality when it advances.
    ///
    /// Called with the execution lock held, so the bus must never block — it
    /// drops slow consumers instead of waiting for them.
    fn publish_block(&self, block: &Block) {
        if self.events.is_empty() {
            return;
        }
        let finalized = self.store.finalized_height();
        self.events.publish(Event::new(
            "heads",
            None,
            serde_json::json!({
                "height": block.height,
                "hash": block.hash,
                "parentHash": block.parent_hash,
                "timestamp": block.timestamp_ms.to_string(),
                "stateRoot": block.state_root,
                "txsRoot": block.txs_root,
                "producer": block.producer,
                "txCount": block.transactions.len(),
                "finalizedHeight": finalized,
                "baseFee": self.store.base_fee().to_string(),
            }),
        ));

        let mut touched: Vec<String> = Vec::new();
        for tx in &block.transactions {
            let hash = tx.hash();
            let from = tx.sender().unwrap_or_default();
            self.events.publish(Event::new(
                "signature",
                Some(hash.clone()),
                serde_json::json!({
                    "hash": hash, "status": "confirmed", "height": block.height,
                    "finalized": block.height <= finalized, "kind": tx.kind.label(),
                    "from": from, "to": tx.to, "fee": tx.fee.to_string(),
                }),
            ));
            for addr in [from.clone(), tx.to.clone()] {
                if !addr.is_empty() && !touched.contains(&addr) {
                    touched.push(addr);
                }
            }
            if matches!(tx.kind, TxKind::CallContract | TxKind::DeployContract) {
                let contract = if matches!(tx.kind, TxKind::CallContract) {
                    tx.to.clone()
                } else {
                    self.store.receipt(&hash).map(|r| r.contract).unwrap_or_default()
                };
                self.events.publish(Event::new(
                    "logs",
                    Some(contract.clone()),
                    serde_json::json!({
                        "contract": contract, "tx": hash, "height": block.height,
                        "caller": from,
                        "receipt": self.store.receipt(&hash),
                    }),
                ));
            }
        }
        for addr in touched {
            let acct = self.store.account(&addr);
            self.events.publish(Event::new(
                "account",
                Some(addr.clone()),
                serde_json::json!({
                    "address": addr, "height": block.height,
                    "balance": acct.balance.to_string(),
                    "balanceInaz": crate::types::format_inaz(acct.balance),
                    "staked": acct.staked.to_string(),
                    "nonce": acct.nonce,
                }),
            ));
        }
        // Finality is announced exactly once per height, however many blocks or
        // vote replays pushed it forward.
        let last = self.announced_final.load(Ordering::Relaxed);
        if finalized > last
            && self
                .announced_final
                .compare_exchange(last, finalized, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.events.publish(Event::new(
                "finality",
                None,
                serde_json::json!({ "finalizedHeight": finalized, "height": block.height }),
            ));
        }
    }

    /// Nonce a new transaction should use, accounting for queued mempool txs.
    pub fn pending_nonce(&self, address: &str) -> u64 {
        let _exec = self.exec_lock.lock().unwrap();
        let acct = self.store.account(address);
        let pool = self.mempool.lock().unwrap();
        acct.nonce + pool.pending_for(address)
    }

    pub fn mempool_size(&self) -> usize {
        self.mempool.lock().unwrap().len()
    }

    /// Current base fee, and the floor a transaction must pay right now.
    pub fn base_fee(&self) -> u128 {
        self.store.base_fee()
    }

    pub fn fee_floor(&self) -> u128 {
        let next = self.store.tip_height().unwrap_or(0) + 1;
        fees::required_fee(next, self.store.base_fee())
    }

    /// Sign and submit an equivocation report from this node's own key. Anyone
    /// can do this; honest validators do it automatically and collect the bounty.
    pub fn submit_report(&self, evidence: &Evidence) -> Result<String, String> {
        let height = self.store.tip_height().unwrap_or(0) + 1;
        slashing::check_report(&self.store, height, &Some(slashing::encode(evidence)))?;
        let mut tx = Transaction {
            kind: TxKind::ReportEquivocation,
            from_pubkey: self.producer.pubkey_hex(),
            to: self.producer.address(),
            amount: 0,
            fee: MIN_FEE,
            nonce: self.pending_nonce(&self.producer.address()),
            chain_id: self.genesis.chain_id,
            payload: Some(slashing::encode(evidence)),
            signature: String::new(),
        };
        tx.signature = self.producer.sign_hex(&tx.signing_bytes());
        let hash = self.accept_tx(tx.clone())?;
        self.gossip_tx(&tx);
        println!("[slash] reported {} at #{} -> {}", evidence.label(), evidence.height(), &hash[..8]);
        Ok(hash)
    }

    /// A peer sent a block for a height we already sealed with a different hash.
    /// If both headers carry the same producer's signature, that is proof of a
    /// double-sign and can be slashed.
    pub fn detect_double_sign(&self, incoming: &Block) -> Option<Evidence> {
        let ours = self.store.block(incoming.height)?;
        if ours.hash == incoming.hash || ours.producer != incoming.producer {
            return None;
        }
        if !incoming.verify_producer() || !ours.verify_producer() {
            return None;
        }
        let evidence = Evidence::Block {
            a: slashing::HeaderProof::from_block(&ours),
            b: slashing::HeaderProof::from_block(incoming),
        };
        evidence.verify().ok().map(|_| evidence)
    }
}
