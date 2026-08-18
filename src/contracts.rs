//! Inazuma Stage 5: WASM smart contracts.
//!
//! Contracts are plain WebAssembly modules. They live at their own base58
//! address, hold INAZ like any account, keep key/value storage inside consensus
//! state, and are metered with fuel bought by the transaction fee.
//!
//! Guest ABI (all imports in module "env"):
//!   inz_input_len() -> i32
//!   inz_input(ptr, cap) -> i32
//!   inz_return(ptr, len)
//!   inz_log(ptr, len)
//!   inz_caller(ptr, cap) -> i32
//!   inz_self(ptr, cap) -> i32
//!   inz_value() -> i64                 attached INAZ in rai
//!   inz_height() -> i64
//!   inz_read(kptr, klen, ptr, cap) -> i32   -1 when the key is unset
//!   inz_write(kptr, klen, vptr, vlen) -> i32
//!   inz_transfer(aptr, alen, amount_rai) -> i32
//! The module must export `invoke() -> i32`; a non-zero return reverts.

use crate::crypto::{is_valid_address, sha256};
use crate::state::Store;
use crate::types::{Payload, RAI_PER_INAZ};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wasmi::core::Trap;
use wasmi::{Caller, Config, Engine, Extern, Linker, Memory, Module, Store as WStore};

/// One-off INAZ burned into the reward pool for putting code on chain.
pub const DEPLOY_FEE: u128 = 5 * RAI_PER_INAZ;
pub const MAX_CODE_BYTES: usize = 256 * 1024;
pub const MAX_INPUT_BYTES: usize = 16 * 1024;
pub const MAX_KEY_BYTES: usize = 128;
pub const MAX_VALUE_BYTES: usize = 8 * 1024;
pub const MAX_WRITES: usize = 512;
pub const MAX_TRANSFERS: usize = 32;
pub const MAX_LOGS: usize = 64;
pub const MAX_RETURN_BYTES: usize = 8 * 1024;
/// Fuel bought per rai of fee, and the ceiling any single call may burn.
pub const FUEL_PER_RAI: u64 = 400;
pub const MAX_FUEL: u64 = 2_000_000_000;
/// Fuel granted to read-only queries served over RPC.
pub const QUERY_FUEL: u64 = 50_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    pub address: String,
    pub code_hash: String,
    pub code_size: usize,
    pub creator: String,
    pub created_height: u64,
    #[serde(default)]
    pub calls: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Receipt {
    pub contract: String,
    pub caller: String,
    pub ok: bool,
    pub fuel_used: u64,
    pub height: u64,
    #[serde(default)]
    pub return_hex: String,
    #[serde(default)]
    pub logs: Vec<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Deterministic contract address: base58 of a 32-byte tag over creator + nonce.
pub fn contract_address(creator: &str, nonce: u64, code_hash: &str) -> String {
    let tag = format!("inazuma-contract|{}|{}|{}", creator, nonce, code_hash);
    bs58::encode(sha256(tag.as_bytes())).into_string()
}

pub fn code_hash(code: &[u8]) -> String {
    hex::encode(sha256(code))
}

fn payload<'a>(p: &'a Option<Payload>) -> Result<&'a Payload, String> {
    p.as_ref()
        .ok_or_else(|| "missing contract payload".to_string())
}

pub fn decode_code(p: &Option<Payload>) -> Result<Vec<u8>, String> {
    let p = payload(p)?;
    let raw = hex::decode(p.code.trim().trim_start_matches("0x"))
        .map_err(|_| "code must be hex-encoded wasm".to_string())?;
    if raw.is_empty() {
        return Err("empty contract code".into());
    }
    if raw.len() > MAX_CODE_BYTES {
        return Err(format!("code too large (max {} bytes)", MAX_CODE_BYTES));
    }
    if raw.len() < 8 || &raw[0..4] != b"\0asm" {
        return Err("not a wasm module".into());
    }
    Ok(raw)
}

pub fn decode_args(p: &Option<Payload>) -> Result<Vec<u8>, String> {
    let args = match p {
        Some(p) => p.args.trim().trim_start_matches("0x").to_string(),
        None => String::new(),
    };
    if args.is_empty() {
        return Ok(Vec::new());
    }
    let raw = hex::decode(&args).map_err(|_| "args must be hex".to_string())?;
    if raw.len() > MAX_INPUT_BYTES {
        return Err("args too large".into());
    }
    Ok(raw)
}

/// Fuel a call may burn, bought with the transaction fee.
pub fn fuel_for_fee(fee: u128) -> u64 {
    let raw = (fee.saturating_mul(FUEL_PER_RAI as u128)).min(MAX_FUEL as u128);
    (raw as u64).max(1_000_000)
}

// ---------------- validation ----------------

pub fn check_deploy(code: &[u8]) -> Result<(), String> {
    let engine = Engine::new(&engine_config());
    Module::new(&engine, code).map_err(|e| format!("invalid wasm: {}", e))?;
    Ok(())
}

pub fn check_call(store: &Store, address: &str) -> Result<Contract, String> {
    if !is_valid_address(address) {
        return Err("invalid contract address".into());
    }
    store
        .contract(address)
        .ok_or_else(|| "no contract at address".to_string())
}

// ---------------- execution ----------------

pub struct Outcome {
    pub ok: bool,
    pub ret: Vec<u8>,
    pub logs: Vec<String>,
    pub fuel_used: u64,
    pub error: Option<String>,
    /// Storage mutations, applied only when `ok`.
    pub writes: Vec<(String, Option<Vec<u8>>)>,
    /// Outgoing INAZ moves, applied only when `ok`.
    pub transfers: Vec<(String, u128)>,
}

impl Outcome {
    fn failed(msg: String, fuel_used: u64) -> Self {
        Outcome {
            ok: false,
            ret: Vec::new(),
            logs: Vec::new(),
            fuel_used,
            error: Some(msg),
            writes: Vec::new(),
            transfers: Vec::new(),
        }
    }

    pub fn receipt(&self, contract: &str, caller: &str, height: u64) -> Receipt {
        Receipt {
            contract: contract.to_string(),
            caller: caller.to_string(),
            ok: self.ok,
            fuel_used: self.fuel_used,
            height,
            return_hex: hex::encode(&self.ret),
            logs: self.logs.clone(),
            error: self.error.clone(),
        }
    }
}

struct Host<'a> {
    store: &'a Store,
    contract: String,
    caller: String,
    value: u128,
    height: u64,
    input: Vec<u8>,
    overlay: HashMap<String, Option<Vec<u8>>>,
    order: Vec<String>,
    logs: Vec<String>,
    ret: Vec<u8>,
    transfers: Vec<(String, u128)>,
    /// INAZ the contract may still send out during this call.
    spendable: u128,
}

impl<'a> Host<'a> {
    fn read_key(&self, key: &str) -> Option<Vec<u8>> {
        match self.overlay.get(key) {
            Some(v) => v.clone(),
            None => self.store.contract_storage(&self.contract, key),
        }
    }
}

fn engine_config() -> Config {
    let mut cfg = Config::default();
    cfg.consume_fuel(true);
    // Deterministic feature set: no threads, no SIMD, no reference types.
    cfg.wasm_bulk_memory(true);
    cfg.wasm_multi_value(false);
    cfg.wasm_mutable_global(true);
    cfg.wasm_sign_extension(true);
    cfg.wasm_saturating_float_to_int(true);
    cfg.floats(false);
    cfg
}

fn memory_of(caller: &mut Caller<'_, Host<'_>>) -> Result<Memory, Trap> {
    caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or_else(|| Trap::new("contract exports no memory"))
}

fn read_bytes(
    caller: &mut Caller<'_, Host<'_>>,
    ptr: i32,
    len: i32,
    max: usize,
) -> Result<Vec<u8>, Trap> {
    if len < 0 || len as usize > max {
        return Err(Trap::new("bad length"));
    }
    let mem = memory_of(caller)?;
    let mut buf = vec![0u8; len as usize];
    mem.read(&caller, ptr as usize, &mut buf)
        .map_err(|_| Trap::new("memory read out of bounds"))?;
    Ok(buf)
}

fn write_out(
    caller: &mut Caller<'_, Host<'_>>,
    ptr: i32,
    cap: i32,
    data: &[u8],
) -> Result<i32, Trap> {
    if cap < 0 {
        return Err(Trap::new("bad capacity"));
    }
    if data.len() > cap as usize {
        // Tell the guest how much room it needs, write nothing.
        return Ok(data.len() as i32);
    }
    let mem = memory_of(caller)?;
    mem.write(caller, ptr as usize, data)
        .map_err(|_| Trap::new("memory write out of bounds"))?;
    Ok(data.len() as i32)
}

/// Run a contract call. Nothing is written to the store: mutations come back in
/// `Outcome` so the caller commits them atomically only on success.
pub fn execute(
    store: &Store,
    contract: &str,
    caller_addr: &str,
    code: &[u8],
    input: Vec<u8>,
    value: u128,
    height: u64,
    fuel: u64,
) -> Outcome {
    let engine = Engine::new(&engine_config());
    let module = match Module::new(&engine, code) {
        Ok(m) => m,
        Err(e) => return Outcome::failed(format!("invalid wasm: {}", e), 0),
    };
    // Attached value is already credited to the contract by the caller, so it
    // is spendable inside this call.
    let spendable = store.account(contract).balance;
    let host = Host {
        store,
        contract: contract.to_string(),
        caller: caller_addr.to_string(),
        value,
        height,
        input,
        overlay: HashMap::new(),
        order: Vec::new(),
        logs: Vec::new(),
        ret: Vec::new(),
        transfers: Vec::new(),
        spendable,
    };
    let mut wstore = WStore::new(&engine, host);
    if wstore.add_fuel(fuel).is_err() {
        return Outcome::failed("fuel setup failed".into(), 0);
    }
    let mut linker: Linker<Host> = Linker::new(&engine);
    if let Err(e) = link_host(&mut linker) {
        return Outcome::failed(format!("host link failed: {}", e), 0);
    }

    let instance = match linker
        .instantiate(&mut wstore, &module)
        .and_then(|i| i.start(&mut wstore))
    {
        Ok(i) => i,
        Err(e) => {
            let used = fuel.saturating_sub(wstore.fuel_consumed().unwrap_or(0));
            let _ = used;
            return Outcome::failed(
                format!("instantiate failed: {}", e),
                wstore.fuel_consumed().unwrap_or(0),
            );
        }
    };
    let invoke = match instance.get_typed_func::<(), i32>(&wstore, "invoke") {
        Ok(f) => f,
        Err(_) => return Outcome::failed("contract exports no invoke()".into(), 0),
    };

    let result = invoke.call(&mut wstore, ());
    let fuel_used = wstore.fuel_consumed().unwrap_or(0);
    let host = wstore.data();
    let logs = host.logs.clone();
    let ret = host.ret.clone();
    let transfers = host.transfers.clone();
    let writes: Vec<(String, Option<Vec<u8>>)> = host
        .order
        .iter()
        .filter_map(|k| host.overlay.get(k).map(|v| (k.clone(), v.clone())))
        .collect();

    match result {
        Ok(0) => Outcome {
            ok: true,
            ret,
            logs,
            fuel_used,
            error: None,
            writes,
            transfers,
        },
        Ok(code) => Outcome {
            ok: false,
            ret,
            logs,
            fuel_used,
            error: Some(format!("contract reverted with code {}", code)),
            writes: Vec::new(),
            transfers: Vec::new(),
        },
        Err(e) => Outcome {
            ok: false,
            ret: Vec::new(),
            logs,
            fuel_used,
            error: Some(trap_message(&e)),
            writes: Vec::new(),
            transfers: Vec::new(),
        },
    }
}

fn trap_message(e: &Trap) -> String {
    let msg = e.to_string();
    if msg.contains("fuel") {
        "out of fuel: raise the fee".to_string()
    } else {
        msg
    }
}

fn link_host(linker: &mut Linker<Host<'_>>) -> Result<(), String> {
    linker
        .func_wrap("env", "inz_input_len", |caller: Caller<'_, Host>| -> i32 {
            caller.data().input.len() as i32
        })
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap(
            "env",
            "inz_input",
            |mut caller: Caller<'_, Host>, ptr: i32, cap: i32| -> Result<i32, Trap> {
                let data = caller.data().input.clone();
                write_out(&mut caller, ptr, cap, &data)
            },
        )
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap(
            "env",
            "inz_return",
            |mut caller: Caller<'_, Host>, ptr: i32, len: i32| -> Result<(), Trap> {
                let data = read_bytes(&mut caller, ptr, len, MAX_RETURN_BYTES)?;
                caller.data_mut().ret = data;
                Ok(())
            },
        )
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap(
            "env",
            "inz_log",
            |mut caller: Caller<'_, Host>, ptr: i32, len: i32| -> Result<(), Trap> {
                let data = read_bytes(&mut caller, ptr, len, 1024)?;
                let host = caller.data_mut();
                if host.logs.len() < MAX_LOGS {
                    host.logs.push(String::from_utf8_lossy(&data).to_string());
                }
                Ok(())
            },
        )
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap(
            "env",
            "inz_caller",
            |mut caller: Caller<'_, Host>, ptr: i32, cap: i32| -> Result<i32, Trap> {
                let v = caller.data().caller.clone();
                write_out(&mut caller, ptr, cap, v.as_bytes())
            },
        )
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap(
            "env",
            "inz_self",
            |mut caller: Caller<'_, Host>, ptr: i32, cap: i32| -> Result<i32, Trap> {
                let v = caller.data().contract.clone();
                write_out(&mut caller, ptr, cap, v.as_bytes())
            },
        )
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap("env", "inz_value", |caller: Caller<'_, Host>| -> i64 {
            caller.data().value.min(i64::MAX as u128) as i64
        })
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap("env", "inz_height", |caller: Caller<'_, Host>| -> i64 {
            caller.data().height as i64
        })
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap("env", "inz_balance", |caller: Caller<'_, Host>| -> i64 {
            let host = caller.data();
            let bal = host.store.account(&host.contract).balance;
            bal.min(i64::MAX as u128) as i64
        })
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap(
            "env",
            "inz_read",
            |mut caller: Caller<'_, Host>,
             kptr: i32,
             klen: i32,
             ptr: i32,
             cap: i32|
             -> Result<i32, Trap> {
                let key = read_bytes(&mut caller, kptr, klen, MAX_KEY_BYTES)?;
                let key = String::from_utf8_lossy(&key).to_string();
                match caller.data().read_key(&key) {
                    None => Ok(-1),
                    Some(v) => write_out(&mut caller, ptr, cap, &v),
                }
            },
        )
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap(
            "env",
            "inz_write",
            |mut caller: Caller<'_, Host>,
             kptr: i32,
             klen: i32,
             vptr: i32,
             vlen: i32|
             -> Result<i32, Trap> {
                let key = read_bytes(&mut caller, kptr, klen, MAX_KEY_BYTES)?;
                let key = String::from_utf8_lossy(&key).to_string();
                if key.is_empty() {
                    return Err(Trap::new("empty storage key"));
                }
                let value = if vlen == 0 {
                    Vec::new()
                } else {
                    read_bytes(&mut caller, vptr, vlen, MAX_VALUE_BYTES)?
                };
                let host = caller.data_mut();
                if !host.overlay.contains_key(&key) {
                    if host.order.len() >= MAX_WRITES {
                        return Err(Trap::new("too many storage writes"));
                    }
                    host.order.push(key.clone());
                }
                // A zero-length write clears the key, keeping state compact.
                host.overlay
                    .insert(key, if value.is_empty() { None } else { Some(value) });
                Ok(0)
            },
        )
        .map_err(|e| e.to_string())?;
    linker
        .func_wrap(
            "env",
            "inz_transfer",
            |mut caller: Caller<'_, Host>,
             aptr: i32,
             alen: i32,
             amount: i64|
             -> Result<i32, Trap> {
                if amount < 0 {
                    return Err(Trap::new("negative amount"));
                }
                let addr = read_bytes(&mut caller, aptr, alen, 64)?;
                let addr = String::from_utf8_lossy(&addr).to_string();
                if !is_valid_address(&addr) {
                    return Ok(-1);
                }
                let amount = amount as u128;
                let host = caller.data_mut();
                if host.transfers.len() >= MAX_TRANSFERS {
                    return Err(Trap::new("too many transfers"));
                }
                if amount > host.spendable {
                    return Ok(-2);
                }
                host.spendable -= amount;
                host.transfers.push((addr, amount));
                Ok(0)
            },
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}
