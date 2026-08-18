//! Inazuma crypto: ed25519 keys, INAZ addresses, hashing.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut b = [0u8; 32];
    b.copy_from_slice(&out);
    b
}

pub fn hash_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// An INAZ address is the base58 encoding of the 32-byte ed25519 public key
/// (Solana-style): no prefix, 43-44 characters, case sensitive.
pub fn address_from_pubkey(pubkey: &[u8; 32]) -> String {
    bs58::encode(pubkey).into_string()
}

/// Recover the raw public key bytes an address encodes.
pub fn pubkey_from_address(addr: &str) -> Option<[u8; 32]> {
    let raw = bs58::decode(addr.trim()).into_vec().ok()?;
    if raw.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Some(out)
}

pub fn is_valid_address(addr: &str) -> bool {
    pubkey_from_address(addr).is_some()
}

pub struct Keypair {
    pub signing: SigningKey,
}

impl Keypair {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("os rng");
        Keypair {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    pub fn from_secret_hex(s: &str) -> Result<Self, String> {
        let raw = hex::decode(s.trim().trim_start_matches("0x")).map_err(|e| e.to_string())?;
        if raw.len() != 32 {
            return Err("secret key must be 32 bytes".into());
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&raw);
        Ok(Keypair {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    pub fn secret_hex(&self) -> String {
        hex::encode(self.signing.to_bytes())
    }

    pub fn pubkey_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.pubkey_bytes())
    }

    pub fn address(&self) -> String {
        address_from_pubkey(&self.pubkey_bytes())
    }

    pub fn sign_hex(&self, msg: &[u8]) -> String {
        hex::encode(self.signing.sign(msg).to_bytes())
    }
}

pub fn verify(pubkey_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
    let pk = match hex::decode(pubkey_hex) {
        Ok(v) if v.len() == 32 => v,
        _ => return false,
    };
    let sg = match hex::decode(sig_hex) {
        Ok(v) if v.len() == 64 => v,
        _ => return false,
    };
    let mut pkb = [0u8; 32];
    pkb.copy_from_slice(&pk);
    let mut sgb = [0u8; 64];
    sgb.copy_from_slice(&sg);
    match VerifyingKey::from_bytes(&pkb) {
        Ok(vk) => vk.verify(msg, &Signature::from_bytes(&sgb)).is_ok(),
        Err(_) => false,
    }
}
