//! Inazuma state store: accounts, blocks, tx index. Backed by an embedded KV store.

use crate::contracts::{Contract, Receipt};
use crate::crypto::sha256;
use crate::journal::Journal;
use crate::smt::Smt;
use crate::tokens::Token;
use crate::types::{Account, Block};
use sled::{Db, Tree};

/// Height at which the sparse Merkle root becomes the consensus state root.
/// Set ahead of the live tip so upgrading nodes replay old history byte-identically.
pub const STATE_ROOT_V2_ACTIVATION_HEIGHT: u64 = 200_000;

pub struct Store {
    _db: Db,
    accounts: Tree,
    blocks: Tree,
    txs: Tree,
    meta: Tree,
    /// Addresses that currently have stake or locked unbonding amounts.
    stakers: Tree,
    /// Native token registry: id -> Token.
    tokens: Tree,
    /// Token ledger: "<token id>:<address>" -> balance.
    token_balances: Tree,
    /// Deployed contracts: address -> Contract.
    contracts: Tree,
    /// Contract bytecode: code hash -> wasm bytes.
    contract_code: Tree,
    /// Contract storage: "<address>:<key>" -> value.
    contract_storage: Tree,
    /// Contract call receipts: tx hash -> Receipt.
    receipts: Tree,
    /// Applied slashes: evidence id -> SlashRecord.
    slashes: Tree,
    /// Sparse Merkle tree nodes over all consensus state.
    smt_nodes: Tree,
    /// Undo log for the block currently executing (see `journal.rs`).
    journal: Journal,
}

/// Stable tree ids for the journal. Order must match `Store::trees()`.
const T_ACCOUNTS: usize = 0;
const T_BLOCKS: usize = 1;
const T_TXS: usize = 2;
const T_META: usize = 3;
const T_STAKERS: usize = 4;
const T_TOKENS: usize = 5;
const T_TOKEN_BALANCES: usize = 6;
const T_CONTRACTS: usize = 7;
const T_CONTRACT_CODE: usize = 8;
const T_CONTRACT_STORAGE: usize = 9;
const T_RECEIPTS: usize = 10;
const T_SLASHES: usize = 11;
pub(crate) const T_SMT: usize = 12;

impl Store {
    pub fn open(path: &str) -> Result<Self, String> {
        let db = sled::open(path).map_err(|e| e.to_string())?;
        Ok(Store {
            accounts: db.open_tree("accounts").map_err(|e| e.to_string())?,
            blocks: db.open_tree("blocks").map_err(|e| e.to_string())?,
            txs: db.open_tree("txs").map_err(|e| e.to_string())?,
            meta: db.open_tree("meta").map_err(|e| e.to_string())?,
            stakers: db.open_tree("stakers").map_err(|e| e.to_string())?,
            tokens: db.open_tree("tokens").map_err(|e| e.to_string())?,
            token_balances: db.open_tree("token_balances").map_err(|e| e.to_string())?,
            contracts: db.open_tree("contracts").map_err(|e| e.to_string())?,
            contract_code: db.open_tree("contract_code").map_err(|e| e.to_string())?,
            contract_storage: db
                .open_tree("contract_storage")
                .map_err(|e| e.to_string())?,
            receipts: db.open_tree("receipts").map_err(|e| e.to_string())?,
            slashes: db.open_tree("slashes").map_err(|e| e.to_string())?,
            smt_nodes: db.open_tree("smt").map_err(|e| e.to_string())?,
            journal: Journal::new(),
            _db: db,
        })
    }

    // ---- atomic block execution ----

    /// Trees in journal-id order.
    fn trees(&self) -> Vec<&Tree> {
        vec![
            &self.accounts,
            &self.blocks,
            &self.txs,
            &self.meta,
            &self.stakers,
            &self.tokens,
            &self.token_balances,
            &self.contracts,
            &self.contract_code,
            &self.contract_storage,
            &self.receipts,
            &self.slashes,
            &self.smt_nodes,
        ]
    }

    /// Start recording writes so a rejected block can be undone completely.
    pub fn begin_block(&self) {
        self.journal.begin();
    }

    /// Keep everything the block wrote.
    pub fn commit_block(&self) {
        self.journal.commit();
    }

    /// Undo every write since `begin_block`, leaving state exactly as it was.
    pub fn abort_block(&self) {
        let trees = self.trees();
        self.journal.rollback(&trees);
    }

    /// Open a savepoint around one transaction. A transaction that fails partway
    /// through its writes must leave nothing behind: it gets dropped from the
    /// block, so any surviving write would put the producer's state root beyond
    /// what an importer replaying that block can reproduce — a permanent fork.
    pub fn begin_tx(&self) {
        self.journal.begin();
    }

    /// Keep this transaction's writes (still undoable if the block is rejected).
    pub fn commit_tx(&self) {
        self.journal.commit();
    }

    /// Undo just this transaction's writes.
    pub fn abort_tx(&self) {
        let trees = self.trees();
        self.journal.rollback(&trees);
    }

    fn jput(&self, id: usize, tree: &Tree, key: &[u8], value: &[u8]) {
        self.journal.record(id, tree, key);
        let _ = tree.insert(key, value);
    }

    fn jdel(&self, id: usize, tree: &Tree, key: &[u8]) {
        self.journal.record(id, tree, key);
        let _ = tree.remove(key);
    }

    // ---- merkleized state ----

    fn smt(&self) -> Smt<'_> {
        Smt::journaled(&self.smt_nodes, &self.journal)
    }

    /// Current Merkle root of all consensus state.
    pub fn merkle_root(&self) -> String {
        self.smt().root_hex()
    }

    /// Inclusion proof for one leaf, for light clients that hold no state.
    /// Returns (root, leafKey, siblings, bitmap of non-empty sibling levels).
    pub fn merkle_proof(&self, domain: &str, key: &str) -> (String, String, Vec<String>, String) {
        let smt = self.smt();
        let (leaf_key, siblings, bitmap) = smt.proof(domain, key.as_bytes());
        (smt.root_hex(), leaf_key, siblings, bitmap)
    }

    /// Canonical leaf value behind a proof, so a verifier can recompute the leaf
    /// hash itself. `None` means the leaf is empty (non-inclusion proof).
    pub fn merkle_leaf_value(&self, domain: &str, key: &str) -> Option<Vec<u8>> {
        let k = key.as_bytes();
        match domain {
            "acct" => self
                .accounts
                .get(k)
                .ok()
                .flatten()
                .and_then(|v| serde_json::from_slice::<Account>(&v).ok())
                .map(|a| Self::account_leaf(&a)),
            "token" => self
                .tokens
                .get(k)
                .ok()
                .flatten()
                .and_then(|v| serde_json::from_slice::<Token>(&v).ok())
                .map(|t| Self::token_leaf(&t)),
            "tokenbal" => self
                .token_balances
                .get(k)
                .ok()
                .flatten()
                .map(|v| v.to_vec()),
            "contract" => self
                .contracts
                .get(k)
                .ok()
                .flatten()
                .and_then(|v| serde_json::from_slice::<Contract>(&v).ok())
                .map(|c| Self::contract_leaf(&c)),
            "cstorage" => self
                .contract_storage
                .get(k)
                .ok()
                .flatten()
                .map(|v| v.to_vec()),
            _ => None,
        }
    }

    /// Consensus state root at `height`: the full-state digest for pre-upgrade
    /// history, the Merkle root from the activation height onward.
    pub fn state_root_at(&self, height: u64) -> String {
        if height < STATE_ROOT_V2_ACTIVATION_HEIGHT {
            self.state_root()
        } else {
            self.merkle_root()
        }
    }

    fn account_leaf(acct: &Account) -> Vec<u8> {
        // Same fields the legacy digest covered: penalties stay out of the root
        // because they are derived from block history, not from transactions.
        format!(
            "{}|{}|{}|{}|{}",
            acct.balance,
            acct.nonce,
            acct.staked,
            acct.unbonding_total(),
            acct.rewards
        )
        .into_bytes()
    }

    fn token_leaf(t: &Token) -> Vec<u8> {
        format!(
            "{}|{}|{}|{}|{}",
            t.symbol, t.decimals, t.supply, t.creator, t.mintable
        )
        .into_bytes()
    }

    fn contract_leaf(c: &Contract) -> Vec<u8> {
        format!("{}|{}|{}", c.code_hash, c.creator, c.created_height).into_bytes()
    }

    /// Build the Merkle tree from current state. Runs once per database, and
    /// again after a reorg wipe, so an upgrading node catches up without a resync.
    pub fn build_merkle_state(&self) {
        let smt = self.smt();
        smt.clear();
        for item in self.accounts.iter().flatten() {
            if let Ok(acct) = serde_json::from_slice::<Account>(&item.1) {
                smt.set("acct", &item.0, Some(&Self::account_leaf(&acct)));
            }
        }
        for item in self.tokens.iter().flatten() {
            if let Ok(t) = serde_json::from_slice::<Token>(&item.1) {
                smt.set("token", &item.0, Some(&Self::token_leaf(&t)));
            }
        }
        for item in self.token_balances.iter().flatten() {
            smt.set("tokenbal", &item.0, Some(&item.1));
        }
        for item in self.contracts.iter().flatten() {
            if let Ok(c) = serde_json::from_slice::<Contract>(&item.1) {
                smt.set("contract", &item.0, Some(&Self::contract_leaf(&c)));
            }
        }
        for item in self.contract_storage.iter().flatten() {
            smt.set("cstorage", &item.0, Some(&item.1));
        }
        let _ = self.smt_nodes.flush();
        self.jput(T_META, &self.meta, b"smt_version", b"1");
        let _ = self.meta.flush();
    }

    /// True when the Merkle tree has been built for this database.
    pub fn merkle_ready(&self) -> bool {
        matches!(self.meta.get(b"smt_version"), Ok(Some(_)))
    }

    // ---- fee market ----

    pub fn base_fee(&self) -> u128 {
        match self.meta.get(b"base_fee") {
            Ok(Some(v)) => String::from_utf8_lossy(&v)
                .parse()
                .unwrap_or(crate::types::MIN_FEE),
            _ => crate::types::MIN_FEE,
        }
    }

    pub fn set_base_fee(&self, fee: u128) {
        self.jput(
            T_META,
            &self.meta,
            b"base_fee",
            &fee.to_string().into_bytes(),
        );
    }

    // ---- contracts ----

    // ---- slashing ----

    pub fn put_slash(&self, record: &crate::slashing::SlashRecord) {
        let v = serde_json::to_vec(record).expect("encode slash");
        self.jput(T_SLASHES, &self.slashes, record.id.as_bytes(), &v);
        let _ = self.slashes.flush();
    }

    pub fn slash(&self, id: &str) -> Option<crate::slashing::SlashRecord> {
        match self.slashes.get(id.as_bytes()) {
            Ok(Some(v)) => serde_json::from_slice(&v).ok(),
            _ => None,
        }
    }

    /// Every slash ever applied, most recent first.
    pub fn slashes(&self) -> Vec<crate::slashing::SlashRecord> {
        let mut out: Vec<crate::slashing::SlashRecord> = self
            .slashes
            .iter()
            .filter_map(|item| item.ok())
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect();
        out.sort_by(|a, b| b.applied_height.cmp(&a.applied_height));
        out
    }

    pub fn contract(&self, address: &str) -> Option<Contract> {
        match self.contracts.get(address.as_bytes()) {
            Ok(Some(v)) => serde_json::from_slice(&v).ok(),
            _ => None,
        }
    }

    pub fn set_contract(&self, c: &Contract) {
        let v = serde_json::to_vec(c).expect("encode contract");
        self.jput(T_CONTRACTS, &self.contracts, c.address.as_bytes(), &v);
        self.smt().set(
            "contract",
            c.address.as_bytes(),
            Some(&Self::contract_leaf(c)),
        );
    }

    pub fn contract_count(&self) -> usize {
        self.contracts.len()
    }

    /// Every deployed contract, newest first.
    pub fn contracts(&self) -> Vec<Contract> {
        let mut out: Vec<Contract> = self
            .contracts
            .iter()
            .filter_map(|item| item.ok())
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect();
        out.sort_by(|a: &Contract, b: &Contract| b.created_height.cmp(&a.created_height));
        out
    }

    pub fn put_code(&self, hash: &str, code: &[u8]) {
        self.jput(T_CONTRACT_CODE, &self.contract_code, hash.as_bytes(), code);
    }

    pub fn code(&self, hash: &str) -> Option<Vec<u8>> {
        match self.contract_code.get(hash.as_bytes()) {
            Ok(Some(v)) => Some(v.to_vec()),
            _ => None,
        }
    }

    fn storage_key(address: &str, key: &str) -> Vec<u8> {
        format!("{}:{}", address, key).into_bytes()
    }

    pub fn contract_storage(&self, address: &str, key: &str) -> Option<Vec<u8>> {
        match self.contract_storage.get(Self::storage_key(address, key)) {
            Ok(Some(v)) => Some(v.to_vec()),
            _ => None,
        }
    }

    pub fn set_contract_storage(&self, address: &str, key: &str, value: Option<&[u8]>) {
        let k = Self::storage_key(address, key);
        match value {
            Some(v) => {
                self.jput(T_CONTRACT_STORAGE, &self.contract_storage, &k, v);
                self.smt().set("cstorage", &k, Some(v));
            }
            None => {
                self.jdel(T_CONTRACT_STORAGE, &self.contract_storage, &k);
                self.smt().set("cstorage", &k, None);
            }
        }
    }

    /// Every stored key of one contract: (key, value bytes).
    pub fn contract_entries(&self, address: &str, limit: usize) -> Vec<(String, Vec<u8>)> {
        let prefix = format!("{}:", address);
        self.contract_storage
            .scan_prefix(prefix.as_bytes())
            .filter_map(|item| item.ok())
            .filter_map(|(k, v)| {
                let key = String::from_utf8_lossy(&k).to_string();
                let short = key.splitn(2, ':').nth(1)?.to_string();
                Some((short, v.to_vec()))
            })
            .take(limit)
            .collect()
    }

    pub fn put_receipt(&self, tx_hash: &str, r: &Receipt) {
        let v = serde_json::to_vec(r).expect("encode receipt");
        self.jput(T_RECEIPTS, &self.receipts, tx_hash.as_bytes(), &v);
    }

    pub fn receipt(&self, tx_hash: &str) -> Option<Receipt> {
        match self.receipts.get(tx_hash.as_bytes()) {
            Ok(Some(v)) => serde_json::from_slice(&v).ok(),
            _ => None,
        }
    }

    pub fn flush_contracts(&self) {
        let _ = self.contracts.flush();
        let _ = self.contract_code.flush();
        let _ = self.contract_storage.flush();
        let _ = self.receipts.flush();
    }

    // ---- native tokens ----

    pub fn token(&self, id: &str) -> Option<Token> {
        match self.tokens.get(id.as_bytes()) {
            Ok(Some(v)) => serde_json::from_slice(&v).ok(),
            _ => None,
        }
    }

    pub fn set_token(&self, token: &Token) {
        let v = serde_json::to_vec(token).expect("encode token");
        self.jput(T_TOKENS, &self.tokens, token.id.as_bytes(), &v);
        self.smt()
            .set("token", token.id.as_bytes(), Some(&Self::token_leaf(token)));
    }

    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }

    /// Every token, in id order.
    pub fn tokens(&self) -> Vec<Token> {
        let mut out: Vec<Token> = self
            .tokens
            .iter()
            .filter_map(|item| item.ok())
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    fn balance_key(token: &str, address: &str) -> Vec<u8> {
        format!("{}:{}", token, address).into_bytes()
    }

    pub fn token_balance(&self, token: &str, address: &str) -> u128 {
        match self.token_balances.get(Self::balance_key(token, address)) {
            Ok(Some(v)) => String::from_utf8_lossy(&v).parse().unwrap_or(0),
            _ => 0,
        }
    }

    fn set_token_balance(&self, token: &str, address: &str, amount: u128) {
        let key = Self::balance_key(token, address);
        if amount == 0 {
            self.jdel(T_TOKEN_BALANCES, &self.token_balances, &key);
            self.smt()
                .set("tokenbal", &Self::balance_key(token, address), None);
        } else {
            let bytes = amount.to_string().into_bytes();
            self.jput(T_TOKEN_BALANCES, &self.token_balances, &key, &bytes);
            self.smt()
                .set("tokenbal", &Self::balance_key(token, address), Some(&bytes));
        }
    }

    /// Mint units to an address and grow the recorded supply and holder count.
    ///
    /// Both additions are checked. Release builds wrap on overflow rather than
    /// panicking, so an unchecked `supply += amount` let a token creator mint
    /// near `u128::MAX` twice and wrap the recorded supply back to a small
    /// number while keeping the balance — free units out of thin air.
    pub fn credit_token(&self, token_id: &str, address: &str, amount: u128) -> Result<(), String> {
        let before = self.token_balance(token_id, address);
        let after = before.checked_add(amount).ok_or("token balance overflow")?;
        if let Some(mut t) = self.token(token_id) {
            t.supply = t
                .supply
                .checked_add(amount)
                .ok_or("token supply overflow")?;
            if before == 0 && amount > 0 {
                t.holders += 1;
            }
            self.set_token(&t);
        }
        self.set_token_balance(token_id, address, after);
        Ok(())
    }

    /// Remove units from an address, shrinking supply (burn) unless re-credited.
    pub fn debit_token(&self, token_id: &str, address: &str, amount: u128) -> Result<(), String> {
        let before = self.token_balance(token_id, address);
        if before < amount {
            return Err("insufficient token balance".into());
        }
        let after = before - amount;
        self.set_token_balance(token_id, address, after);
        if let Some(mut t) = self.token(token_id) {
            t.supply = t.supply.saturating_sub(amount);
            if after == 0 {
                t.holders = t.holders.saturating_sub(1);
            }
            self.set_token(&t);
        }
        Ok(())
    }

    /// Every token balance an address holds: (token, balance).
    pub fn token_holdings(&self, address: &str) -> Vec<(Token, u128)> {
        self.tokens()
            .into_iter()
            .filter_map(|t| {
                let bal = self.token_balance(&t.id, address);
                if bal > 0 {
                    Some((t, bal))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Holders of one token, largest first.
    pub fn token_holders(&self, token_id: &str, limit: usize) -> Vec<(String, u128)> {
        let prefix = format!("{}:", token_id);
        let mut out: Vec<(String, u128)> = self
            .token_balances
            .scan_prefix(prefix.as_bytes())
            .filter_map(|item| item.ok())
            .filter_map(|(k, v)| {
                let key = String::from_utf8_lossy(&k).to_string();
                let addr = key.split(':').nth(1)?.to_string();
                let bal: u128 = String::from_utf8_lossy(&v).parse().ok()?;
                Some((addr, bal))
            })
            .collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        out.truncate(limit);
        out
    }

    pub fn flush_tokens(&self) {
        let _ = self.tokens.flush();
        let _ = self.token_balances.flush();
    }

    // ---- accounts ----

    pub fn account(&self, address: &str) -> Account {
        match self.accounts.get(address.as_bytes()) {
            Ok(Some(v)) => serde_json::from_slice(&v).unwrap_or_default(),
            _ => Account::default(),
        }
    }

    pub fn set_account(&self, address: &str, acct: &Account) {
        let v = serde_json::to_vec(acct).expect("encode account");
        self.jput(T_ACCOUNTS, &self.accounts, address.as_bytes(), &v);
        self.smt()
            .set("acct", address.as_bytes(), Some(&Self::account_leaf(acct)));
        if acct.staked > 0 || !acct.unbonding.is_empty() {
            self.jput(T_STAKERS, &self.stakers, address.as_bytes(), b"1");
        } else {
            self.jdel(T_STAKERS, &self.stakers, address.as_bytes());
        }
    }

    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Deterministic root over every account, in key order.
    pub fn state_root(&self) -> String {
        let mut buf: Vec<u8> = Vec::new();
        for item in self.accounts.iter() {
            if let Ok((k, v)) = item {
                let acct: Account = serde_json::from_slice(&v).unwrap_or_default();
                buf.extend_from_slice(&k);
                buf.extend_from_slice(
                    format!(
                        "|{}|{}|{}|{}|{}|",
                        acct.balance,
                        acct.nonce,
                        acct.staked,
                        acct.unbonding_total(),
                        acct.rewards
                    )
                    .as_bytes(),
                );
            }
        }
        // Token registry and ledger are part of consensus state, so peers that
        // disagree about a token balance fail the state root check.
        for item in self.tokens.iter() {
            if let Ok((k, v)) = item {
                if let Ok(t) = serde_json::from_slice::<Token>(&v) {
                    buf.extend_from_slice(&k);
                    buf.extend_from_slice(
                        format!(
                            "|{}|{}|{}|{}|{}|",
                            t.symbol, t.decimals, t.supply, t.creator, t.mintable
                        )
                        .as_bytes(),
                    );
                }
            }
        }
        for item in self.token_balances.iter() {
            if let Ok((k, v)) = item {
                buf.extend_from_slice(&k);
                buf.extend_from_slice(b"=");
                buf.extend_from_slice(&v);
                buf.extend_from_slice(b"|");
            }
        }
        // Contract code identity and storage are consensus state too.
        for item in self.contracts.iter() {
            if let Ok((k, v)) = item {
                if let Ok(c) = serde_json::from_slice::<Contract>(&v) {
                    buf.extend_from_slice(&k);
                    buf.extend_from_slice(
                        format!("|{}|{}|{}|", c.code_hash, c.creator, c.created_height).as_bytes(),
                    );
                }
            }
        }
        for item in self.contract_storage.iter() {
            if let Ok((k, v)) = item {
                buf.extend_from_slice(&k);
                buf.extend_from_slice(b"=");
                buf.extend_from_slice(&v);
                buf.extend_from_slice(b"|");
            }
        }
        hex::encode(sha256(&buf))
    }

    pub fn total_supply(&self) -> u128 {
        let mut total: u128 = 0;
        for item in self.accounts.iter() {
            if let Ok((_, v)) = item {
                let acct: Account = serde_json::from_slice(&v).unwrap_or_default();
                total += acct.balance + acct.staked + acct.unbonding_total();
            }
        }
        total
    }

    pub fn total_staked(&self) -> u128 {
        let mut total: u128 = 0;
        for (_, acct) in self.stake_accounts() {
            total += acct.staked;
        }
        total
    }

    /// Every account with stake or a pending unbond, in address order.
    pub fn stake_accounts(&self) -> Vec<(String, Account)> {
        let mut out = Vec::new();
        for item in self.stakers.iter() {
            if let Ok((k, _)) = item {
                let addr = String::from_utf8_lossy(&k).to_string();
                let acct = self.account(&addr);
                out.push((addr, acct));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    pub fn flush_stakers(&self) {
        let _ = self.stakers.flush();
    }

    pub fn flush_state_tree(&self) {
        let _ = self.smt_nodes.flush();
    }

    // ---- blocks ----

    pub fn put_block(&self, block: &Block) {
        let v = serde_json::to_vec(block).expect("encode block");
        self.jput(T_BLOCKS, &self.blocks, &block.height.to_be_bytes(), &v);
        for tx in &block.transactions {
            self.jput(
                T_TXS,
                &self.txs,
                tx.hash().as_bytes(),
                &block.height.to_be_bytes(),
            );
        }
        self.jput(
            T_META,
            &self.meta,
            b"tip_height",
            &block.height.to_be_bytes(),
        );
        self.jput(T_META, &self.meta, b"tip_hash", block.hash.as_bytes());
        let _ = self.blocks.flush();
        let _ = self.meta.flush();
        let _ = self.accounts.flush();
        let _ = self.txs.flush();
    }

    pub fn block(&self, height: u64) -> Option<Block> {
        match self.blocks.get(height.to_be_bytes()) {
            Ok(Some(v)) => serde_json::from_slice(&v).ok(),
            _ => None,
        }
    }

    pub fn tx_height(&self, hash: &str) -> Option<u64> {
        match self.txs.get(hash.as_bytes()) {
            Ok(Some(v)) if v.len() == 8 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&v);
                Some(u64::from_be_bytes(b))
            }
            _ => None,
        }
    }

    pub fn tx_count(&self) -> usize {
        self.txs.len()
    }

    pub fn tip_height(&self) -> Option<u64> {
        match self.meta.get(b"tip_height") {
            Ok(Some(v)) if v.len() == 8 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&v);
                Some(u64::from_be_bytes(b))
            }
            _ => None,
        }
    }

    pub fn tip_hash(&self) -> String {
        match self.meta.get(b"tip_hash") {
            Ok(Some(v)) => String::from_utf8_lossy(&v).to_string(),
            _ => String::new(),
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.tip_height().is_some()
    }

    // ---- finality ----

    /// Highest height that carries more than 2/3 of staked INAZ in precommits.
    pub fn finalized_height(&self) -> u64 {
        match self.meta.get(b"finalized_height") {
            Ok(Some(v)) if v.len() == 8 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&v);
                u64::from_be_bytes(b)
            }
            _ => 0,
        }
    }

    pub fn set_finalized_height(&self, height: u64) {
        if height <= self.finalized_height() {
            return;
        }
        self.jput(
            T_META,
            &self.meta,
            b"finalized_height",
            &height.to_be_bytes(),
        );
        let _ = self.meta.flush();
    }

    /// Clear accounts, blocks and indexes so the chain can be replayed from
    /// genesis. The finalized height is kept as a safety floor.
    pub fn reset_chain(&self) {
        let _ = self.accounts.clear();
        let _ = self.blocks.clear();
        let _ = self.txs.clear();
        let _ = self.stakers.clear();
        let _ = self.tokens.clear();
        let _ = self.token_balances.clear();
        let _ = self.contracts.clear();
        let _ = self.contract_storage.clear();
        let _ = self.receipts.clear();
        let _ = self.slashes.clear();
        let _ = self.smt_nodes.clear();
        let _ = self.meta.remove(b"tip_height");
        let _ = self.meta.remove(b"tip_hash");
        let _ = self.accounts.flush();
        let _ = self.blocks.flush();
        let _ = self.txs.flush();
        let _ = self.stakers.flush();
        self.flush_tokens();
        self.flush_contracts();
        let _ = self.meta.flush();
    }
}

// ---- operator surface: halt, pruning, snapshots ----

/// Tables a state snapshot carries. Blocks, the tx index and receipts are
/// history, not state, so they are not part of a snapshot.
pub const SNAPSHOT_TABLES: &[&str] = &[
    "accounts",
    "stakers",
    "tokens",
    "token_balances",
    "contracts",
    "contract_code",
    "contract_storage",
    "slashes",
];

impl Store {
    fn table(&self, name: &str) -> Option<&Tree> {
        Some(match name {
            "accounts" => &self.accounts,
            "stakers" => &self.stakers,
            "tokens" => &self.tokens,
            "token_balances" => &self.token_balances,
            "contracts" => &self.contracts,
            "contract_code" => &self.contract_code,
            "contract_storage" => &self.contract_storage,
            "slashes" => &self.slashes,
            "receipts" => &self.receipts,
            _ => return None,
        })
    }

    /// Every key/value in a snapshot table, in key order.
    pub fn raw_dump(&self, name: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
        let Some(tree) = self.table(name) else {
            return Vec::new();
        };
        tree.iter()
            .flatten()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect()
    }

    /// Replace a snapshot table wholesale. Snapshot import only.
    pub fn raw_restore(&self, name: &str, entries: &[(Vec<u8>, Vec<u8>)]) -> Result<(), String> {
        let tree = self
            .table(name)
            .ok_or_else(|| format!("unknown table {}", name))?;
        tree.clear().map_err(|e| e.to_string())?;
        for (k, v) in entries {
            tree.insert(k.as_slice(), v.as_slice())
                .map_err(|e| e.to_string())?;
        }
        tree.flush().map_err(|e| e.to_string())?;
        Ok(())
    }

    // ---- emergency halt ----

    /// Freeze this node: it stops sealing, voting, admitting and importing.
    /// Operator action, persisted so a restart cannot silently unfreeze a node
    /// that was halted for a consensus bug.
    pub fn set_halt(&self, reason: &str) {
        self.jput(T_META, &self.meta, b"halt_reason", reason.as_bytes());
        let _ = self.meta.flush();
    }

    pub fn clear_halt(&self) {
        self.jdel(T_META, &self.meta, b"halt_reason");
        let _ = self.meta.flush();
    }

    pub fn halt_reason(&self) -> Option<String> {
        match self.meta.get(b"halt_reason") {
            Ok(Some(v)) => Some(String::from_utf8_lossy(&v).to_string()),
            _ => None,
        }
    }

    // ---- pruning ----

    /// Lowest height whose block body is still stored. 0 means nothing pruned.
    pub fn pruned_below(&self) -> u64 {
        match self.meta.get(b"pruned_below") {
            Ok(Some(v)) if v.len() == 8 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&v);
                u64::from_be_bytes(b)
            }
            _ => 0,
        }
    }

    /// Record that history below `height` is absent (snapshot import).
    pub fn mark_pruned_below(&self, height: u64) {
        self.jput(T_META, &self.meta, b"pruned_below", &height.to_be_bytes());
        let _ = self.meta.flush();
    }

    /// Drop block bodies, their tx index entries and receipts below `below`.
    ///
    /// Only finalized history is ever eligible, and height 0 (genesis) is kept
    /// so a node can always prove which chain it is on. State itself is never
    /// touched: the Merkle tree and every account stay complete, so a pruned
    /// node still validates and serves current state. Pruned nodes cannot serve
    /// historical blocks to a syncing peer — run an archive node for that.
    pub fn prune_blocks(&self, below: u64) -> usize {
        let ceiling = self.finalized_height();
        let below = below.min(ceiling);
        if below <= 1 {
            return 0;
        }
        let mut removed = 0usize;
        for height in self.pruned_below().max(1)..below {
            let key = height.to_be_bytes();
            let Ok(Some(raw)) = self.blocks.get(key) else {
                continue;
            };
            if let Ok(block) = serde_json::from_slice::<Block>(&raw) {
                for tx in &block.transactions {
                    let h = tx.hash();
                    let _ = self.txs.remove(h.as_bytes());
                    let _ = self.receipts.remove(h.as_bytes());
                }
            }
            let _ = self.blocks.remove(key);
            removed += 1;
        }
        if removed > 0 {
            self.jput(T_META, &self.meta, b"pruned_below", &below.to_be_bytes());
            let _ = self.blocks.flush();
            let _ = self.txs.flush();
            let _ = self.receipts.flush();
            let _ = self.meta.flush();
        }
        removed
    }
}
