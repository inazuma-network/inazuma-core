//! Transaction preflight: answer "would this succeed?" without touching state.
//!
//! Sending a transaction to find out whether it was valid is an expensive way to
//! ask a question. Preflight runs every admission and execution check the node
//! would run — chain id, fee floor against the live base fee, signature, nonce
//! position including what the pool already holds, funding, and the rules for the
//! specific transaction kind — and reports the verdict plus the exact cost. It
//! writes nothing, takes no execution lock, and cannot be used to jump the queue.

use crate::chain::Node;
use crate::contracts::{self, DEPLOY_FEE};
use crate::crypto::is_valid_address;
use crate::fees;
use crate::tokens::{self, TOKEN_CREATION_FEE};
use crate::types::{format_inaz, Transaction, TxKind, MIN_FEE};
use serde_json::{json, Value};

/// Total INAZ the sender's balance must cover for this transaction.
pub fn debit_for(tx: &Transaction) -> u128 {
    match tx.kind {
        TxKind::Unstake | TxKind::ReportEquivocation | TxKind::Unjail => tx.fee,
        TxKind::CreateToken => tx.fee + TOKEN_CREATION_FEE,
        TxKind::MintToken | TxKind::TokenTransfer | TxKind::BurnToken => tx.fee,
        TxKind::DeployContract => tx.fee + DEPLOY_FEE + tx.amount,
        _ => tx.amount + tx.fee,
    }
}

/// Run every check, collecting *all* problems instead of stopping at the first,
/// so one round trip tells a client everything it has to fix.
pub fn preflight(node: &Node, tx: &Transaction) -> Value {
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    let next_height = node.store.tip_height().unwrap_or(0) + 1;
    let floor = fees::required_fee(next_height, node.store.base_fee());

    if tx.chain_id != node.genesis.chain_id {
        errors.push(format!(
            "wrong chain id: transaction says {}, this chain is {}",
            tx.chain_id, node.genesis.chain_id
        ));
    }
    if tx.fee < MIN_FEE {
        errors.push(format!("fee below protocol minimum ({} rai)", MIN_FEE));
    } else if tx.fee < floor {
        errors.push(format!("fee below current base fee ({} rai)", floor));
    }

    let signature_ok = tx.verify_signature();
    if !signature_ok {
        errors.push("invalid signature".into());
    }
    let sender = tx.sender();
    if sender.is_none() {
        errors.push("invalid sender public key".into());
    }

    let mut expected_nonce = None;
    let mut balance = 0u128;
    let mut balance_after = None;
    let debit = debit_for(tx);

    if let Some(sender) = sender.as_deref() {
        let acct = node.store.account(sender);
        let pending = node.pending_nonce(sender);
        expected_nonce = Some(pending);
        balance = acct.balance;
        if tx.nonce != pending {
            errors.push(format!("bad nonce: expected {}, got {}", pending, tx.nonce));
        }
        match tx.kind {
            TxKind::Unstake => {
                if tx.amount == 0 {
                    errors.push("unstake amount must be positive".into());
                } else if acct.staked < tx.amount {
                    errors.push("not enough staked".into());
                }
            }
            TxKind::Stake => {
                if tx.amount == 0 {
                    errors.push("stake amount must be positive".into());
                }
            }
            TxKind::Transfer => {
                if !is_valid_address(&tx.to) {
                    errors.push("invalid recipient address".into());
                }
            }
            TxKind::CreateToken => {
                if let Err(e) = tokens::check_create(&node.store, sender, tx.nonce, &tx.payload) {
                    errors.push(e);
                }
            }
            TxKind::MintToken => {
                if let Err(e) =
                    tokens::check_mint(&node.store, sender, &tx.to, tx.amount, &tx.payload)
                {
                    errors.push(e);
                }
            }
            TxKind::TokenTransfer => {
                if let Err(e) = tokens::check_token_transfer(
                    &node.store,
                    sender,
                    &tx.to,
                    tx.amount,
                    &tx.payload,
                ) {
                    errors.push(e);
                }
            }
            TxKind::BurnToken => {
                if let Err(e) = tokens::check_burn(&node.store, sender, tx.amount, &tx.payload) {
                    errors.push(e);
                }
            }
            TxKind::DeployContract => match contracts::decode_code(&tx.payload) {
                Ok(code) => {
                    if let Err(e) = contracts::check_deploy(&code) {
                        errors.push(e);
                    }
                }
                Err(e) => errors.push(e),
            },
            TxKind::CallContract => {
                if let Err(e) = contracts::check_call(&node.store, &tx.to) {
                    errors.push(e);
                }
                if let Err(e) = contracts::decode_args(&tx.payload) {
                    errors.push(e);
                }
            }
            TxKind::ReportEquivocation | TxKind::Unjail => {}
        }
        if balance < debit {
            errors.push(format!(
                "insufficient balance: need {} INAZ, have {}",
                format_inaz(debit),
                format_inaz(balance)
            ));
        } else {
            balance_after = Some(balance - debit);
        }
        if node.store.tx_height(&tx.hash()).is_some() {
            errors.push("this transaction is already on chain".into());
        }
    }

    // A transaction paying exactly the floor is valid now, but the floor moves
    // with demand, so tell the caller instead of letting it fail later.
    if errors.is_empty() && tx.fee < floor.saturating_mul(2) {
        warnings.push("fee is close to the current base fee; it may be crowded out if demand rises".into());
    }

    json!({
        "ok": errors.is_empty(),
        "hash": tx.hash(),
        "kind": tx.kind.label(),
        "from": sender,
        "to": tx.to,
        "signatureValid": signature_ok,
        "chainId": node.genesis.chain_id,
        "height": next_height,
        "expectedNonce": expected_nonce,
        "baseFee": node.store.base_fee().to_string(),
        "feeFloor": floor.to_string(),
        "fee": tx.fee.to_string(),
        "totalDebit": debit.to_string(),
        "totalDebitInaz": format_inaz(debit),
        "balance": balance.to_string(),
        "balanceAfter": balance_after.map(|b| b.to_string()),
        "balanceAfterInaz": balance_after.map(format_inaz),
        "errors": errors,
        "warnings": warnings,
    })
}
