//! Core Inazuma types: accounts, transactions, blocks, genesis.

use crate::crypto::{address_from_pubkey, hash_hex, sha256, verify};
use serde::{Deserialize, Serialize};

/// Smallest unit of INAZ. 1 INAZ = 1_000_000_000 rai (9 decimals).
pub const RAI_PER_INAZ: u128 = 1_000_000_000;
pub const CHAIN_ID: u64 = 7777;
pub const MIN_FEE: u128 = 1_000; // 0.000001 INAZ

/// Stake required for an account to enter the validator set.
pub const MIN_STAKE: u128 = 1_000 * RAI_PER_INAZ;
/// Blocks an unstaked amount stays locked before it is spendable again.
pub const UNBONDING_BLOCKS: u64 = 300;

// ---- slashing parameters ----

/// Height at which downtime accounting and jailing switch on. Set ahead of the
/// live tip so upgrading nodes replay existing history byte-identically.
pub const SLASHING_ACTIVATION_HEIGHT: u64 = 130_000;
/// Floor burn for signing two conflicting blocks or votes at the same height.
pub const EQUIVOCATION_MIN_BURN_PCT: u128 = 5;
/// Correlation multiplier: burn scales with the offender's share of total stake,
/// so a whale that equivocates loses far more than a small validator.
pub const EQUIVOCATION_CORRELATION_FACTOR: u128 = 3;
/// Cut of the burn paid to whoever submitted the proof.
pub const REPORTER_BOUNTY_PCT: u128 = 10;
/// Consecutive missed slots before a validator is jailed for downtime.
pub const DOWNTIME_JAIL_STREAK: u64 = 50;
/// Blocks a downtime jail lasts before `unjail` is accepted.
pub const DOWNTIME_JAIL_BLOCKS: u64 = 10_000;
/// Burn applied on a repeat downtime jail, in basis points of stake (0.1%).
pub const DOWNTIME_REPEAT_BURN_BPS: u128 = 10;
/// Evidence older than this many blocks is rejected: past the unbonding window
/// there is nothing left to punish.
pub const EVIDENCE_MAX_AGE_BLOCKS: u64 = 100_000;
/// Sentinel jail height for a permanently removed (tombstoned) validator.
pub const TOMBSTONE_HEIGHT: u64 = u64::MAX;

pub fn format_inaz(rai: u128) -> String {
    let whole = rai / RAI_PER_INAZ;
    let frac = rai % RAI_PER_INAZ;
    format!("{}.{:09}", whole, frac)
}

pub fn parse_inaz(s: &str) -> Result<u128, String> {
    let s = s.trim();
    let (w, f) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    let whole: u128 = w.parse().map_err(|_| "bad amount".to_string())?;
    let mut frac = f.to_string();
    if frac.len() > 9 {
        return Err("max 9 decimals".into());
    }
    while frac.len() < 9 {
        frac.push('0');
    }
    let frac: u128 = if frac.is_empty() { 0 } else { frac.parse().map_err(|_| "bad amount".to_string())? };
    Ok(whole * RAI_PER_INAZ + frac)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Unbond {
    pub amount: u128,
    pub release_height: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Account {
    #[serde(default)]
    pub balance: u128,
    #[serde(default)]
    pub nonce: u64,
    #[serde(default)]
    pub staked: u128,
    /// Amounts unstaked but still locked, each with the height it unlocks at.
    #[serde(default)]
    pub unbonding: Vec<Unbond>,
    /// Lifetime staking rewards credited to this account.
    #[serde(default)]
    pub rewards: u128,
    /// Blocks this account has produced as elected leader.
    #[serde(default)]
    pub blocks_produced: u64,
    /// Liveness and slashing record for this validator.
    #[serde(default)]
    pub penalties: Penalties,
}

/// Slashing state lives on the account but stays out of the state root: it is
/// derived deterministically from block history, so adding it does not fork the
/// chain or invalidate blocks sealed before the upgrade.

/// Slashing / liveness bookkeeping kept on the account.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Penalties {
    /// Height the validator becomes electable again. `TOMBSTONE_HEIGHT` = never.
    #[serde(default)]
    pub jailed_until: u64,
    /// Permanently removed for equivocation. Never electable again.
    #[serde(default)]
    pub tombstoned: bool,
    /// Lifetime INAZ burned by slashing.
    #[serde(default)]
    pub slashed: u128,
    /// Lifetime slots this validator was elected for and did not seal.
    #[serde(default)]
    pub missed_slots: u64,
    /// Consecutive missed slots; reset whenever the validator seals a block.
    #[serde(default)]
    pub missed_streak: u64,
    /// How many times this validator has been jailed for downtime.
    #[serde(default)]
    pub downtime_jails: u64,
}

impl Account {
    pub fn unbonding_total(&self) -> u128 {
        self.unbonding.iter().map(|u| u.amount).sum()
    }

    pub fn is_validator(&self) -> bool {
        self.staked >= MIN_STAKE
    }
}

impl Account {
    /// Bonded, not jailed and not tombstoned at `height`.
    pub fn is_active_validator(&self, height: u64) -> bool {
        self.is_validator() && !self.penalties.tombstoned && self.penalties.jailed_until <= height
    }

    pub fn is_jailed(&self, height: u64) -> bool {
        self.penalties.tombstoned || self.penalties.jailed_until > height
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TxKind {
    Transfer,
    Stake,
    Unstake,
    /// Submit proof that a validator signed two conflicting blocks or votes.
    ReportEquivocation,
    /// Ask to leave a downtime jail once the jail period has passed.
    Unjail,
    /// Create a new native token.
    CreateToken,
    /// Mint more of a mintable token to an address.
    MintToken,
    /// Move native token units between accounts.
    TokenTransfer,
    /// Permanently destroy token units held by the sender.
    BurnToken,
    /// Put a WASM contract on chain.
    DeployContract,
    /// Execute a deployed contract.
    CallContract,
}

impl TxKind {
    fn tag(&self) -> &'static str {
        match self {
            TxKind::Transfer => "transfer",
            TxKind::Stake => "stake",
            TxKind::Unstake => "unstake",
            TxKind::ReportEquivocation => "reportequivocation",
            TxKind::Unjail => "unjail",
            TxKind::CreateToken => "createtoken",
            TxKind::MintToken => "minttoken",
            TxKind::TokenTransfer => "tokentransfer",
            TxKind::BurnToken => "burntoken",
            TxKind::DeployContract => "deploycontract",
            TxKind::CallContract => "callcontract",
        }
    }

    pub fn label(&self) -> &'static str {
        self.tag()
    }

    pub fn is_token(&self) -> bool {
        matches!(
            self,
            TxKind::CreateToken | TxKind::MintToken | TxKind::TokenTransfer | TxKind::BurnToken
        )
    }

    pub fn is_contract(&self) -> bool {
        matches!(self, TxKind::DeployContract | TxKind::CallContract)
    }
}

/// Extra fields carried by token transactions. Part of the signed bytes, so a
/// payload can never be altered in flight.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Payload {
    /// Token id, for mint / transfer / burn.
    #[serde(default)]
    pub token: String,
    /// Ticker, for creation.
    #[serde(default)]
    pub symbol: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub decimals: u8,
    #[serde(default)]
    pub mintable: bool,
    /// Hex WASM bytecode, deploy only.
    #[serde(default)]
    pub code: String,
    /// Hex call input handed to the contract.
    #[serde(default)]
    pub args: String,
}

impl Payload {
    pub fn signing_part(&self) -> String {
        let base = format!(
            "{}|{}|{}|{}|{}",
            self.token, self.symbol, self.name, self.decimals, self.mintable
        );
        // Contract fields only extend the signed bytes when present, so token
        // and transfer signatures stay byte-for-byte compatible.
        if self.code.is_empty() && self.args.is_empty() {
            base
        } else {
            format!("{}|{}|{}", base, self.code, self.args)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub kind: TxKind,
    /// Sender public key, hex. The sender address is derived from it.
    pub from_pubkey: String,
    pub to: String,
    pub amount: u128,
    pub fee: u128,
    pub nonce: u64,
    pub chain_id: u64,
    /// Only present on token transactions.
    #[serde(default)]
    pub payload: Option<Payload>,
    #[serde(default)]
    pub signature: String,
}

impl Transaction {
    /// Canonical bytes that get signed. Deterministic, no JSON ambiguity.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let base = format!(
            "inazuma-tx|{}|{}|{}|{}|{}|{}|{}",
            self.chain_id, self.kind.tag(), self.from_pubkey, self.to, self.amount, self.fee, self.nonce
        );
        match &self.payload {
            // Legacy transfers keep byte-for-byte compatible signing bytes.
            None => base.into_bytes(),
            Some(p) => format!("{}|{}", base, p.signing_part()).into_bytes(),
        }
    }

    pub fn hash(&self) -> String {
        let mut b = self.signing_bytes();
        b.extend_from_slice(self.signature.as_bytes());
        hash_hex(&b)
    }

    pub fn sender(&self) -> Option<String> {
        let raw = hex::decode(&self.from_pubkey).ok()?;
        if raw.len() != 32 {
            return None;
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&raw);
        Some(address_from_pubkey(&pk))
    }

    pub fn verify_signature(&self) -> bool {
        verify(&self.from_pubkey, &self.signing_bytes(), &self.signature)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub height: u64,
    pub parent_hash: String,
    pub timestamp_ms: u128,
    pub state_root: String,
    pub txs_root: String,
    pub producer: String,
    /// Producer's public key, hex. Peers verify the block signature with it and
    /// check that `producer` really derives from it.
    #[serde(default)]
    pub producer_pubkey: String,
    pub transactions: Vec<Transaction>,
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub hash: String,
}

pub fn txs_root(txs: &[Transaction]) -> String {
    if txs.is_empty() {
        return hash_hex(b"inazuma-empty");
    }
    let mut level: Vec<[u8; 32]> = txs
        .iter()
        .map(|t| sha256(t.hash().as_bytes()))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::new();
        for pair in level.chunks(2) {
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&pair[0]);
            buf.extend_from_slice(pair.get(1).unwrap_or(&pair[0]));
            next.push(sha256(&buf));
        }
        level = next;
    }
    hex::encode(level[0])
}

impl Block {
    pub fn header_bytes(&self) -> Vec<u8> {
        format!(
            "inazuma-block|{}|{}|{}|{}|{}|{}|{}|{}",
            CHAIN_ID,
            self.height,
            self.parent_hash,
            self.timestamp_ms,
            self.state_root,
            self.txs_root,
            self.producer,
            self.producer_pubkey
        )
        .into_bytes()
    }

    pub fn compute_hash(&self) -> String {
        let mut b = self.header_bytes();
        b.extend_from_slice(self.signature.as_bytes());
        hash_hex(&b)
    }

    /// The producer signed this exact header and owns the producer address.
    pub fn verify_producer(&self) -> bool {
        let raw = match hex::decode(&self.producer_pubkey) {
            Ok(v) if v.len() == 32 => v,
            _ => return false,
        };
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&raw);
        if address_from_pubkey(&pk) != self.producer {
            return false;
        }
        if self.hash != self.compute_hash() {
            return false;
        }
        verify(&self.producer_pubkey, &self.header_bytes(), &self.signature)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAlloc {
    pub address: String,
    /// Human-readable INAZ amount, e.g. "1000000".
    pub balance: String,
    /// Optional INAZ bonded at genesis, so the chain boots with a validator set.
    #[serde(default)]
    pub stake: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Genesis {
    pub chain_id: u64,
    pub chain_name: String,
    pub symbol: String,
    pub decimals: u8,
    pub block_time_ms: u64,
    pub alloc: Vec<GenesisAlloc>,
}

impl Genesis {
    pub fn default_devnet(admin: &str) -> Self {
        Genesis {
            chain_id: CHAIN_ID,
            chain_name: "Inazuma".into(),
            symbol: "INAZ".into(),
            decimals: 9,
            block_time_ms: 400,
            alloc: vec![GenesisAlloc {
                address: admin.to_string(),
                balance: "1000000".into(),
                stake: None,
            }],
        }
    }
}
