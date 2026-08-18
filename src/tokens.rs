//! Inazuma native token module: fungible assets (memes, game currencies, points)
//! as a first-class part of the state machine — no virtual machine required.
//!
//! Every token is created by an account, has its own id, supply and holder set,
//! and moves with the same signed transaction format as INAZ. Fees are always
//! paid in INAZ, so INAZ stays the only gas and staking coin.

use crate::crypto::{is_valid_address, sha256};
use crate::state::Store;
use crate::types::{Payload, RAI_PER_INAZ};
use serde::{Deserialize, Serialize};

/// INAZ burned into the validator reward pool for creating a token.
/// High enough that spam costs real money, low enough for any creator.
pub const TOKEN_CREATION_FEE: u128 = 10 * RAI_PER_INAZ;
pub const MAX_DECIMALS: u8 = 18;
pub const MAX_SYMBOL_LEN: usize = 10;
pub const MAX_NAME_LEN: usize = 40;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub id: String,
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    pub supply: u128,
    pub creator: String,
    /// When false the supply is fixed forever at creation.
    pub mintable: bool,
    pub created_height: u64,
    pub holders: u64,
}

/// Deterministic token id: derived from creator, nonce and symbol so two nodes
/// executing the same transaction always agree on the id.
pub fn token_id(creator: &str, nonce: u64, symbol: &str) -> String {
    let h = sha256(format!("inazuma-token|{}|{}|{}", creator, nonce, symbol).as_bytes());
    format!("tk{}", hex::encode(&h[..8]))
}

pub fn normalize_symbol(raw: &str) -> Result<String, String> {
    let s = raw.trim().to_ascii_uppercase();
    if s.len() < 2 || s.len() > MAX_SYMBOL_LEN {
        return Err(format!("symbol must be 2-{} characters", MAX_SYMBOL_LEN));
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("symbol must be letters and digits only".into());
    }
    Ok(s)
}

/// Format a raw token amount using that token's decimals.
pub fn format_units(amount: u128, decimals: u8) -> String {
    if decimals == 0 {
        return amount.to_string();
    }
    let scale = 10u128.pow(decimals as u32);
    format!(
        "{}.{:0width$}",
        amount / scale,
        amount % scale,
        width = decimals as usize
    )
}

pub fn parse_units(s: &str, decimals: u8) -> Result<u128, String> {
    let s = s.trim();
    let (w, f) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    let whole: u128 = w.parse().map_err(|_| "bad amount".to_string())?;
    if f.len() > decimals as usize {
        return Err(format!("max {} decimals", decimals));
    }
    let mut frac = f.to_string();
    while frac.len() < decimals as usize {
        frac.push('0');
    }
    let frac: u128 = if frac.is_empty() {
        0
    } else {
        frac.parse().map_err(|_| "bad amount".to_string())?
    };
    Ok(whole * 10u128.pow(decimals as u32) + frac)
}

fn payload(p: &Option<Payload>) -> Result<&Payload, String> {
    p.as_ref()
        .ok_or_else(|| "token transaction missing payload".into())
}

// ---- validation used by the mempool (no state writes) ----

pub fn check_create(
    store: &Store,
    sender: &str,
    nonce: u64,
    p: &Option<Payload>,
) -> Result<(), String> {
    let p = payload(p)?;
    let symbol = normalize_symbol(&p.symbol)?;
    if p.name.trim().is_empty() || p.name.len() > MAX_NAME_LEN {
        return Err(format!("name must be 1-{} characters", MAX_NAME_LEN));
    }
    if p.decimals > MAX_DECIMALS {
        return Err(format!("decimals must be 0-{}", MAX_DECIMALS));
    }
    if store.token(&token_id(sender, nonce, &symbol)).is_some() {
        return Err("token already exists".into());
    }
    Ok(())
}

pub fn check_mint(
    store: &Store,
    sender: &str,
    to: &str,
    amount: u128,
    p: &Option<Payload>,
) -> Result<(), String> {
    let p = payload(p)?;
    let token = store.token(&p.token).ok_or("unknown token")?;
    if token.creator != sender {
        return Err("only the token creator can mint".into());
    }
    if !token.mintable {
        return Err("token supply is fixed".into());
    }
    if amount == 0 {
        return Err("mint amount must be positive".into());
    }
    if !is_valid_address(to) {
        return Err("invalid recipient address".into());
    }
    Ok(())
}

pub fn check_token_transfer(
    store: &Store,
    sender: &str,
    to: &str,
    amount: u128,
    p: &Option<Payload>,
) -> Result<(), String> {
    let p = payload(p)?;
    let token = store.token(&p.token).ok_or("unknown token")?;
    if amount == 0 {
        return Err("amount must be positive".into());
    }
    if !is_valid_address(to) {
        return Err("invalid recipient address".into());
    }
    if store.token_balance(&token.id, sender) < amount {
        return Err("insufficient token balance".into());
    }
    Ok(())
}

pub fn check_burn(
    store: &Store,
    sender: &str,
    amount: u128,
    p: &Option<Payload>,
) -> Result<(), String> {
    let p = payload(p)?;
    let token = store.token(&p.token).ok_or("unknown token")?;
    if amount == 0 {
        return Err("amount must be positive".into());
    }
    if store.token_balance(&token.id, sender) < amount {
        return Err("insufficient token balance".into());
    }
    Ok(())
}

// ---- execution (state writes) ----

/// Create a token and mint the initial supply to the creator.
/// Returns the extra INAZ consumed as the creation fee.
pub fn apply_create(
    store: &Store,
    sender: &str,
    nonce: u64,
    initial_supply: u128,
    height: u64,
    p: &Option<Payload>,
) -> Result<String, String> {
    let p = payload(p)?;
    let symbol = normalize_symbol(&p.symbol)?;
    if p.decimals > MAX_DECIMALS {
        return Err("decimals too large".into());
    }
    let id = token_id(sender, nonce, &symbol);
    if store.token(&id).is_some() {
        return Err("token already exists".into());
    }
    let token = Token {
        id: id.clone(),
        symbol,
        name: p.name.trim().to_string(),
        decimals: p.decimals,
        supply: 0,
        creator: sender.to_string(),
        mintable: p.mintable,
        created_height: height,
        holders: 0,
    };
    store.set_token(&token);
    if initial_supply > 0 {
        store.credit_token(&id, sender, initial_supply)?;
    }
    Ok(id)
}

pub fn apply_mint(
    store: &Store,
    sender: &str,
    to: &str,
    amount: u128,
    p: &Option<Payload>,
) -> Result<(), String> {
    let p = payload(p)?;
    let token = store.token(&p.token).ok_or("unknown token")?;
    if token.creator != sender || !token.mintable {
        return Err("not allowed to mint this token".into());
    }
    store.credit_token(&token.id, to, amount)?;
    Ok(())
}

pub fn apply_token_transfer(
    store: &Store,
    sender: &str,
    to: &str,
    amount: u128,
    p: &Option<Payload>,
) -> Result<(), String> {
    let p = payload(p)?;
    let token = store.token(&p.token).ok_or("unknown token")?;
    if sender == to {
        return Ok(());
    }
    store.debit_token(&token.id, sender, amount)?;
    store.credit_token(&token.id, to, amount)?;
    Ok(())
}

pub fn apply_burn(
    store: &Store,
    sender: &str,
    amount: u128,
    p: &Option<Payload>,
) -> Result<(), String> {
    let p = payload(p)?;
    let token = store.token(&p.token).ok_or("unknown token")?;
    store.debit_token(&token.id, sender, amount)?;
    Ok(())
}
