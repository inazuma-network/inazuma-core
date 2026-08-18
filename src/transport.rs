//! Encrypted, authenticated P2P transport for Inazuma ("INSC1").
//!
//! Raw TCP JSON lines let anyone on the path read gossip, forge blocks/votes
//! toward a node, or partition it silently. This module wraps every peer
//! connection in an authenticated key exchange followed by an AEAD framed
//! channel, in the spirit of Noise/TLS 1.3 but small enough to audit in one
//! sitting:
//!
//!   initiator -> "INSC1" || e_i (32)
//!   responder -> e_r (32) || nodekey_r (32) || sig_r (64)   over h1
//!   initiator -> nodekey_i (32) || sig_i (64)               over h2
//!
//!   h1  = SHA256("INSC1" || e_i || e_r)
//!   h2  = SHA256(h1 || nodekey_r || "initiator")
//!   ikm = X25519(e_i, e_r)
//!   k_i2r, k_r2i = HKDF-SHA256(salt = h1, ikm, info = "inazuma/p2p/v1/...")
//!
//! Ephemeral X25519 gives forward secrecy; the ed25519 node-key signature over
//! the transcript authenticates the peer (SIGMA-style), so a man in the middle
//! cannot splice its own ephemeral key in. The verified node identity is handed
//! back to the caller, which is what makes an allowlist (and per-identity, not
//! just per-IP, scoring) possible against eclipse attacks.
//!
//! Frames are `u32` big-endian length + ChaCha20-Poly1305 ciphertext with a
//! per-direction counter nonce, so replay or reorder inside a session fails to
//! decrypt.

use crate::crypto::Keypair;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use hkdf::Hkdf;
use serde_json::Value;
use sha2::Sha256;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use x25519_dalek::{PublicKey, StaticSecret};

pub const MAGIC: &[u8; 5] = b"INSC1";
/// Anything larger is either a bug or an attempt to exhaust memory.
pub const MAX_FRAME: usize = 8 * 1024 * 1024;

fn kdf(salt: &[u8; 32], ikm: &[u8; 32], info: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0u8; 32];
    hk.expand(info.as_bytes(), &mut out).expect("hkdf len");
    out
}

fn transcript1(ei: &[u8; 32], er: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(69);
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(ei);
    buf.extend_from_slice(er);
    crate::crypto::sha256(&buf)
}

fn transcript2(h1: &[u8; 32], responder_key: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(73);
    buf.extend_from_slice(h1);
    buf.extend_from_slice(responder_key);
    buf.extend_from_slice(b"initiator");
    crate::crypto::sha256(&buf)
}

fn verify_raw(pubkey: &[u8; 32], msg: &[u8; 32], sig: &[u8; 64]) -> bool {
    match VerifyingKey::from_bytes(pubkey) {
        Ok(vk) => vk.verify(msg, &Signature::from_bytes(sig)).is_ok(),
        Err(_) => false,
    }
}

fn read_exact(stream: &mut TcpStream, n: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

fn arr32(v: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(&v[..32]);
    a
}

fn arr64(v: &[u8]) -> [u8; 64] {
    let mut a = [0u8; 64];
    a.copy_from_slice(&v[..64]);
    a
}

pub(crate) struct Aead2 {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl Aead2 {
    fn new(key: [u8; 32]) -> Self {
        Aead2 {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
            counter: 0,
        }
    }

    fn nonce(&mut self) -> Nonce {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&self.counter.to_le_bytes());
        self.counter = self.counter.wrapping_add(1);
        *Nonce::from_slice(&n)
    }

    fn seal(&mut self, plain: &[u8]) -> Result<Vec<u8>, String> {
        let n = self.nonce();
        self.cipher
            .encrypt(
                &n,
                Payload {
                    msg: plain,
                    aad: MAGIC,
                },
            )
            .map_err(|_| "seal failed".to_string())
    }

    fn open(&mut self, ct: &[u8]) -> Result<Vec<u8>, String> {
        let n = self.nonce();
        self.cipher
            .decrypt(
                &n,
                Payload {
                    msg: ct,
                    aad: MAGIC,
                },
            )
            .map_err(|_| "decrypt failed (wrong key, replay or tampering)".to_string())
    }
}

/// One peer connection: either an encrypted INSC1 session or, while a network is
/// mid-upgrade, a legacy newline-JSON socket.
pub enum Channel {
    Secure {
        stream: TcpStream,
        send: Aead2,
        recv: Aead2,
        peer_id: String,
    },
    Plain {
        reader: BufReader<TcpStream>,
        writer: TcpStream,
        /// Bytes already consumed off the socket while sniffing for INSC1; they
        /// are the head of the first legacy JSON line.
        prefix: Vec<u8>,
    },
}

impl Channel {
    /// Hex ed25519 node key of the peer, proven by signature. `None` on legacy
    /// plaintext connections, which is exactly why they score worse.
    pub fn peer_id(&self) -> Option<&str> {
        match self {
            Channel::Secure { peer_id, .. } => Some(peer_id),
            Channel::Plain { .. } => None,
        }
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self, Channel::Secure { .. })
    }

    pub fn send(&mut self, msg: &Value) -> Result<(), String> {
        let body = serde_json::to_vec(msg).map_err(|e| e.to_string())?;
        match self {
            Channel::Secure { stream, send, .. } => {
                let ct = send.seal(&body)?;
                if ct.len() > MAX_FRAME {
                    return Err("frame too large".into());
                }
                let mut out = Vec::with_capacity(ct.len() + 4);
                out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
                out.extend_from_slice(&ct);
                stream.write_all(&out).map_err(|e| e.to_string())?;
                stream.flush().map_err(|e| e.to_string())
            }
            Channel::Plain { writer, .. } => {
                writer.write_all(&body).map_err(|e| e.to_string())?;
                writer.write_all(b"\n").map_err(|e| e.to_string())?;
                writer.flush().map_err(|e| e.to_string())
            }
        }
    }

    /// Next message, or `Ok(None)` when the peer closed the connection.
    /// `Err` means malformed input: the caller should penalize and hang up.
    pub fn recv(&mut self) -> Result<Option<Value>, String> {
        match self {
            Channel::Secure { stream, recv, .. } => {
                let mut len = [0u8; 4];
                if let Err(e) = stream.read_exact(&mut len) {
                    return if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        Ok(None)
                    } else {
                        Err(e.to_string())
                    };
                }
                let n = u32::from_be_bytes(len) as usize;
                if n == 0 || n > MAX_FRAME {
                    return Err("bad frame length".into());
                }
                let ct = read_exact(stream, n)?;
                let plain = recv.open(&ct)?;
                serde_json::from_slice(&plain)
                    .map(Some)
                    .map_err(|e| e.to_string())
            }
            Channel::Plain { reader, prefix, .. } => {
                let mut line = String::from_utf8(std::mem::take(prefix)).unwrap_or_default();
                let read = reader.read_line(&mut line).map_err(|e| e.to_string())?;
                if read == 0 && line.is_empty() {
                    return Ok(None);
                }
                if line.len() > MAX_FRAME {
                    return Err("oversized line".into());
                }
                if line.trim().is_empty() {
                    return Ok(Some(Value::Null));
                }
                serde_json::from_str(&line)
                    .map(Some)
                    .map_err(|e| e.to_string())
            }
        }
    }
}

/// Client side of the handshake on an already connected socket.
pub fn handshake_initiator(mut stream: TcpStream, id: &Keypair) -> Result<Channel, String> {
    let e_secret = ephemeral_secret();
    let ei = PublicKey::from(&e_secret).to_bytes();

    let mut hello = Vec::with_capacity(37);
    hello.extend_from_slice(MAGIC);
    hello.extend_from_slice(&ei);
    stream.write_all(&hello).map_err(|e| e.to_string())?;
    stream.flush().ok();

    let res = read_exact(&mut stream, 32 + 32 + 64)?;
    let er = arr32(&res[0..32]);
    let peer_key = arr32(&res[32..64]);
    let peer_sig = arr64(&res[64..128]);

    let h1 = transcript1(&ei, &er);
    if !verify_raw(&peer_key, &h1, &peer_sig) {
        return Err("peer failed to authenticate (bad handshake signature)".into());
    }

    let h2 = transcript2(&h1, &peer_key);
    let sig = id.signing.sign(&h2).to_bytes();
    let mut fin = Vec::with_capacity(96);
    fin.extend_from_slice(&id.pubkey_bytes());
    fin.extend_from_slice(&sig);
    stream.write_all(&fin).map_err(|e| e.to_string())?;
    stream.flush().ok();

    let shared = e_secret.diffie_hellman(&PublicKey::from(er)).to_bytes();
    Ok(Channel::Secure {
        stream,
        send: Aead2::new(kdf(&h1, &shared, "inazuma/p2p/v1/i2r")),
        recv: Aead2::new(kdf(&h1, &shared, "inazuma/p2p/v1/r2i")),
        peer_id: hex::encode(peer_key),
    })
}

/// Server side. `first` is the bytes already peeked off the socket while
/// deciding whether this is an INSC1 peer or a legacy plaintext one.
pub fn handshake_responder(
    mut stream: TcpStream,
    id: &Keypair,
    ei: [u8; 32],
) -> Result<Channel, String> {
    let e_secret = ephemeral_secret();
    let er = PublicKey::from(&e_secret).to_bytes();
    let h1 = transcript1(&ei, &er);

    let sig = id.signing.sign(&h1).to_bytes();
    let mut msg = Vec::with_capacity(128);
    msg.extend_from_slice(&er);
    msg.extend_from_slice(&id.pubkey_bytes());
    msg.extend_from_slice(&sig);
    stream.write_all(&msg).map_err(|e| e.to_string())?;
    stream.flush().ok();

    let fin = read_exact(&mut stream, 96)?;
    let peer_key = arr32(&fin[0..32]);
    let peer_sig = arr64(&fin[32..96]);
    let h2 = transcript2(&h1, &id.pubkey_bytes());
    if !verify_raw(&peer_key, &h2, &peer_sig) {
        return Err("peer failed to authenticate (bad handshake signature)".into());
    }

    let shared = e_secret.diffie_hellman(&PublicKey::from(ei)).to_bytes();
    Ok(Channel::Secure {
        stream,
        send: Aead2::new(kdf(&h1, &shared, "inazuma/p2p/v1/r2i")),
        recv: Aead2::new(kdf(&h1, &shared, "inazuma/p2p/v1/i2r")),
        peer_id: hex::encode(peer_key),
    })
}

pub fn plain_channel(stream: TcpStream, prefix: Vec<u8>) -> Result<Channel, String> {
    let writer = stream.try_clone().map_err(|e| e.to_string())?;
    Ok(Channel::Plain {
        reader: BufReader::new(stream),
        writer,
        prefix,
    })
}

/// A fresh X25519 scalar from the OS RNG. Discarded with the session, which is
/// what gives the channel forward secrecy.
fn ephemeral_secret() -> StaticSecret {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("os rng");
    StaticSecret::from(seed)
}
