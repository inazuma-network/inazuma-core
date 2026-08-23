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
/// Effective activation height for *this* node's chain. The mainnet-track chain
/// keeps the constant above so upgrading nodes replay existing history
/// byte-identically; a brand-new genesis (public testnet, devnet, adversarial
/// harness) may set `slashing_activation_height` and get slashing from block 1.
/// It is chain identity, not an operator knob — it comes from genesis only.
pub static SLASHING_ACTIVATION: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(SLASHING_ACTIVATION_HEIGHT);

/// Called once at boot, from genesis. Never call this at runtime: two nodes with
/// different activation heights would disagree on liveness accounting and fork.
pub fn set_slashing_activation(h: u64) {
    SLASHING_ACTIVATION.store(h, std::sync::atomic::Ordering::Relaxed);
}

pub fn slashing_activation() -> u64 {
    SLASHING_ACTIVATION.load(std::sync::atomic::Ordering::Relaxed)
}
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

/// Height at which downtime jailing is retired (Ethereum-style liveness).
/// From this height on, missing slots only costs rewards — a validator is never
/// removed from the active set for being briefly offline, and any existing
/// downtime jail becomes inert. Provable faults (equivocation) still tombstone.
///
/// **Already activated, and activated retroactively.** The rule shipped after
/// the devnet had passed this height (tip was ~1.40M–1.52M during the rollout),
/// so blocks in `[NO_DOWNTIME_JAIL_HEIGHT, RETRO_FORK_DEPLOY_HEIGHT)` were
/// produced under the old active-set rules and are replayed under the new ones.
/// That window can only differ if a validator carried a downtime jail while
/// producing or voting inside it; `verify-history` replays genesis→tip and any
/// second client MUST reproduce the same result. Every future rule change is
/// gated at a height strictly greater than the current tip (see
/// `INACTIVITY_LEAK_ACTIVATION_HEIGHT`) so this never happens again.
pub const NO_DOWNTIME_JAIL_HEIGHT: u64 = 1_400_000;

/// Height the no-downtime-jail code was actually deployed to the public network.
/// Purely informational: it documents the retroactive window above.
pub const RETRO_FORK_DEPLOY_HEIGHT: u64 = 1_403_733;

/// Height the inactivity leak activates. Strictly in the future when merged.
/// Removing downtime jails alone leaves an offline validator counting toward the
/// 2/3 finality denominator forever, so >1/3 dark stake stalls the chain with no
/// way to shrink the set. From this height a validator that keeps missing slots
/// has its bond decayed per missed slot; once the bond falls under `MIN_STAKE`
/// it leaves the active set on its own and the denominator shrinks. Coming back
/// online stops the decay immediately — the offline cost is gradual, not a jail.
pub const INACTIVITY_LEAK_ACTIVATION_HEIGHT: u64 = 2_000_000;

/// Consecutive missed slots before the leak starts biting.
pub const INACTIVITY_LEAK_STREAK: u64 = 50;

/// Bond decay per missed slot once leaking, in basis points (0.05%).
pub const INACTIVITY_LEAK_BPS: u128 = 5;

/// True while downtime still jails, i.e. before the liveness fork.
pub fn downtime_jail_enabled(height: u64) -> bool {
    height < NO_DOWNTIME_JAIL_HEIGHT
}

/// True once the inactivity leak replaces downtime jailing as the liveness cost.
pub fn inactivity_leak_enabled(height: u64) -> bool {
    height >= INACTIVITY_LEAK_ACTIVATION_HEIGHT
}

// ---- sync awareness ----

/// Highest block height any peer has reported to this node. Updated by the p2p
/// sync loop and read by block production, which must not seal a block while
/// this node is behind: sealing on a stale tip creates a local fork that then
/// has to be repaired by a full replay, and a 2 vCPU box can lose that race
/// forever. Lives here so `chain` can read it without depending on `p2p`.
pub static BEST_PEER_HEIGHT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How far behind the best known peer this node may be and still produce.
/// One slot of jitter is normal; more than that means we are genuinely lagging.
pub const PRODUCE_LAG_TOLERANCE: u64 = 2;

pub fn note_peer_height(height: u64) {
    use std::sync::atomic::Ordering;
    BEST_PEER_HEIGHT.fetch_max(height, Ordering::Relaxed);
}

pub fn best_peer_height() -> u64 {
    BEST_PEER_HEIGHT.load(std::sync::atomic::Ordering::Relaxed)
}

/// Serde helper: carry a `u128` as a JSON string.
///
/// Internally tagged enums (`#[serde(tag = "kind")]`) buffer their contents
/// through serde's `Content` type, which cannot represent 128-bit integers —
/// deserializing such a field fails with "u128 is not supported". Any u128 that
/// travels inside a tagged enum (e.g. equivocation evidence headers) must use
/// this module, or the message can be produced but never parsed.
pub mod u128_str {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        // Accept both the string form and a plain number, so older peers and
        // hand-written RPC payloads keep working.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Either {
            S(String),
            N(u64),
        }
        match Either::deserialize(d)? {
            Either::S(s) => s.parse().map_err(serde::de::Error::custom),
            Either::N(n) => Ok(n as u128),
        }
    }
}

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
    let frac: u128 = if frac.is_empty() {
        0
    } else {
        frac.parse().map_err(|_| "bad amount".to_string())?
    };
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
    /// True when `jailed_until` was set by a provable fault (equivocation), not
    /// by downtime. Fault jails are never forgiven by the liveness rules: only
    /// the reason distinguishes them, so the sentinel value must not be used as
    /// a proxy for "this jail is safe to clear".
    #[serde(default)]
    pub jail_fault: bool,
    /// Lifetime bond decayed by the inactivity leak.
    #[serde(default)]
    pub leaked: u128,
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
        if self.is_validator() && self.penalties.tombstoned {
            return false;
        }
        if !self.is_validator() {
            return false;
        }
        if !downtime_jail_enabled(height) {
            // Downtime jails no longer gate participation; tombstones still do.
            return self.penalties.jailed_until != TOMBSTONE_HEIGHT;
        }
        self.penalties.jailed_until <= height
    }

    pub fn is_jailed(&self, height: u64) -> bool {
        if self.penalties.tombstoned || self.penalties.jailed_until == TOMBSTONE_HEIGHT {
            return true;
        }
        downtime_jail_enabled(height) && self.penalties.jailed_until > height
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Move public INAZ into the shielded pool, creating private notes.
    Shield,
    /// Move value between shielded notes. Amounts and parties are hidden;
    /// validity is proven with a Groth16 spend proof.
    PrivateTransfer,
    /// Exit the shielded pool: burn notes, credit a public address.
    Unshield,
}

impl TxKind {
    pub fn tag(&self) -> &'static str {
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
            TxKind::Shield => "shield",
            TxKind::PrivateTransfer => "privatetransfer",
            TxKind::Unshield => "unshield",
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

    pub fn is_shielded(&self) -> bool {
        matches!(
            self,
            TxKind::Shield | TxKind::PrivateTransfer | TxKind::Unshield
        )
    }
}

/// Zcash-style shielded data. Every field is a string so the transaction JSON
/// stays plain: field elements are 0x-prefixed 32-byte hex, amounts decimal.
/// Part of the signed bytes (v2 preimage only — shielded kinds never sign v1).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShieldedData {
    /// Commitment-tree root the spend proof anchors to.
    #[serde(default)]
    pub anchor: String,
    /// Revealed nullifiers of the spent notes (hex field elements).
    #[serde(default)]
    pub nullifiers: Vec<String>,
    /// Commitments of the notes created by this transaction.
    #[serde(default)]
    pub commitments: Vec<String>,
    /// Groth16 proof, hex. Empty for Shield (public value in, no proof needed).
    #[serde(default)]
    pub proof: String,
    /// Public value leaving the pool (Unshield), in rai, decimal.
    #[serde(default)]
    pub public_unshield: String,
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

/// The signed preimage joins fields with `|`, so a field that itself contains a
/// `|` could shift the field boundaries and make one signature valid for two
/// different transactions. Every signed string field is therefore required to
/// be delimiter-free; this is checked before a signature is ever trusted, which
/// makes the encoding unambiguous without changing the preimage format (and so
/// without a hard fork).
pub fn delimiter_free(s: &str) -> bool {
    !s.contains('|')
}

/// Canonical, length-prefixed encoding of a signed field.
///
/// The `|`-joined preimage above is unambiguous only because every signed
/// string is checked for `|` first — a validation band-aid rather than an
/// encoding. This is the real fix: each field is written as its byte length
/// (u32, big endian) followed by its bytes, so no field content can ever shift
/// another field's boundary, whatever characters it contains.
pub fn push_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn push_str(buf: &mut Vec<u8>, s: &str) {
    push_field(buf, s.as_bytes());
}

/// Domain tag for the canonical transaction preimage. Distinct from the legacy
/// `inazuma-tx|...` prefix, so a signature over one encoding can never be
/// reinterpreted as a signature over the other.
pub const TX_DOMAIN_V2: &[u8] = b"inazuma-tx-v2";

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
    /// Only present on shielded transactions.
    #[serde(default)]
    pub shielded: Option<ShieldedData>,
    #[serde(default)]
    pub signature: String,
}

impl Transaction {
    /// True when no signed field can shift the preimage's field boundaries.
    pub fn fields_unambiguous(&self) -> bool {
        if !delimiter_free(&self.from_pubkey) || !delimiter_free(&self.to) {
            return false;
        }
        match &self.payload {
            None => true,
            Some(p) => {
                delimiter_free(&p.token)
                    && delimiter_free(&p.symbol)
                    && delimiter_free(&p.name)
                    && delimiter_free(&p.code)
                    && delimiter_free(&p.args)
            }
        }
    }

    /// Canonical bytes that get signed. Deterministic, no JSON ambiguity.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let base = format!(
            "inazuma-tx|{}|{}|{}|{}|{}|{}|{}",
            self.chain_id,
            self.kind.tag(),
            self.from_pubkey,
            self.to,
            self.amount,
            self.fee,
            self.nonce
        );
        match &self.payload {
            // Legacy transfers keep byte-for-byte compatible signing bytes.
            None => base.into_bytes(),
            Some(p) => format!("{}|{}", base, p.signing_part()).into_bytes(),
        }
    }

    /// Canonical (v2) preimage: domain tag plus every field length-prefixed.
    /// Structurally unambiguous, so it needs no `|` validation at all.
    ///
    /// Both encodings are accepted by `verify_signature` during the migration:
    /// history signed with the legacy preimage must keep replaying byte-identically,
    /// while new signers (node CLI, wallet, extension) can move to v2 without a
    /// coordinated fork. The legacy path stays guarded by `fields_unambiguous`.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(256);
        push_field(&mut b, TX_DOMAIN_V2);
        b.extend_from_slice(&self.chain_id.to_be_bytes());
        push_str(&mut b, self.kind.tag());
        push_str(&mut b, &self.from_pubkey);
        push_str(&mut b, &self.to);
        b.extend_from_slice(&self.amount.to_be_bytes());
        b.extend_from_slice(&self.fee.to_be_bytes());
        b.extend_from_slice(&self.nonce.to_be_bytes());
        match &self.payload {
            None => b.push(0),
            Some(p) => {
                b.push(1);
                push_str(&mut b, &p.token);
                push_str(&mut b, &p.symbol);
                push_str(&mut b, &p.name);
                b.push(p.decimals);
                b.push(u8::from(p.mintable));
                push_str(&mut b, &p.code);
                push_str(&mut b, &p.args);
            }
        }
        // Shielded data is signed too: an anchor or nullifier swapped in
        // flight must invalidate the signature.
        match &self.shielded {
            None => b.push(0),
            Some(s) => {
                b.push(1);
                push_str(&mut b, &s.anchor);
                b.extend_from_slice(&(s.nullifiers.len() as u32).to_be_bytes());
                for n in &s.nullifiers {
                    push_str(&mut b, n);
                }
                b.extend_from_slice(&(s.commitments.len() as u32).to_be_bytes());
                for c in &s.commitments {
                    push_str(&mut b, c);
                }
                push_str(&mut b, &s.proof);
                push_str(&mut b, &s.public_unshield);
            }
        }
        b
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
        // Shielded kinds sign the v2 preimage only: v1 has no encoding for
        // their fields, so accepting it would leave them unsigned.
        if self.kind.is_shielded() {
            return verify(
                &self.from_pubkey,
                &self.canonical_signing_bytes(),
                &self.signature,
            );
        }
        // v2 first: it is unambiguous by construction.
        if verify(
            &self.from_pubkey,
            &self.canonical_signing_bytes(),
            &self.signature,
        ) {
            return true;
        }
        self.fields_unambiguous()
            && verify(&self.from_pubkey, &self.signing_bytes(), &self.signature)
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
    let mut level: Vec<[u8; 32]> = txs.iter().map(|t| sha256(t.hash().as_bytes())).collect();
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
    /// Optional. Omitted on the mainnet-track chain, which uses
    /// `SLASHING_ACTIVATION_HEIGHT`.
    #[serde(default)]
    pub slashing_activation_height: Option<u64>,
}

impl Genesis {
    pub fn default_devnet(admin: &str) -> Self {
        Genesis {
            chain_id: CHAIN_ID,
            chain_name: "Inazuma".into(),
            symbol: "INAZ".into(),
            decimals: 9,
            block_time_ms: 400,
            slashing_activation_height: None,
            alloc: vec![GenesisAlloc {
                address: admin.to_string(),
                balance: "1000000".into(),
                stake: None,
            }],
        }
    }
}

#[cfg(test)]
mod signing_tests {
    use super::*;

    fn tx(to: &str, payload: Option<Payload>) -> Transaction {
        Transaction {
            kind: TxKind::Transfer,
            from_pubkey: "ab".repeat(32),
            to: to.to_string(),
            amount: 1,
            fee: MIN_FEE,
            nonce: 0,
            chain_id: CHAIN_ID,
            payload,
            signature: String::new(),
            shielded: None,
        }
    }

    #[test]
    fn delimiter_injection_is_refused() {
        // Without the guard these two produce the same signed preimage, so one
        // signature would authorise both.
        let a = tx("alice|1|2", None);
        let b = tx("alice", None);
        assert!(!a.fields_unambiguous());
        assert!(b.fields_unambiguous());
        // A forged signature can never be accepted on an ambiguous tx.
        assert!(!a.verify_signature());
    }

    #[test]
    fn payload_fields_are_checked_too() {
        let mut p = Payload::default();
        p.symbol = "IN|AZ".into();
        assert!(!tx("alice", Some(p)).fields_unambiguous());
    }

    #[test]
    fn distinct_txs_never_share_signing_bytes() {
        let a = tx("alice", None);
        let mut b = tx("alice", None);
        b.nonce = 1;
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }
}
