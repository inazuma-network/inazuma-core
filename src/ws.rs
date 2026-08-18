//! Inazuma WebSocket endpoint: live subscriptions plus the full JSON-RPC surface
//! over one long-lived socket.
//!
//! Two jobs:
//!   * `inaz_subscribe` / `inaz_unsubscribe` — the node pushes new blocks,
//!     finality, pool admissions, one transaction's fate, one account's balance
//!     or contract activity the instant it happens.
//!   * every ordinary RPC method, so a client that already holds this socket does
//!     not pay a TCP and TLS handshake per read.
//!
//! The protocol is implemented directly (RFC 6455 framing, SHA-1 handshake) to
//! keep the node free of extra dependencies. Every abuse guard the HTTP endpoint
//! has applies here too, plus limits that only matter for long-lived sockets:
//! bounded subscriptions per connection, bounded frame size, idle ping/timeout,
//! and non-blocking delivery so a stalled reader can never stall the chain.

use crate::chain::Node;
use crate::events::{self, Channel, SubSender, MAX_SUBS_PER_CONN};
use crate::limits::{ConnGuard, IpConnCounter};
use crate::rpc;
use crate::rpcauth::{self, RpcConfig, Tier};
use serde_json::{json, Value};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_LIVE_SOCKETS: usize = 2_048;
const MAX_SOCKETS_PER_IP: usize = 16;
/// Largest single client message. Bulk submission over a socket is allowed, but
/// bounded — an unbounded frame length is a one-packet memory attack.
const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;
/// Idle period after which the server pings; two missed intervals close it.
const PING_EVERY: Duration = Duration::from_secs(20);
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

static NEXT_CONN: AtomicU64 = AtomicU64::new(1);

pub fn serve(node: Arc<Node>, addr: &str, cfg: Arc<RpcConfig>) -> Result<(), String> {
    let listener = TcpListener::bind(addr).map_err(|e| e.to_string())?;
    println!("[ws] listening on ws://{} (subscriptions + json-rpc)", addr);
    let conns = Arc::new(ConnGuard::new(MAX_LIVE_SOCKETS));
    let per_ip = Arc::new(IpConnCounter::new(MAX_SOCKETS_PER_IP));
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let node = Arc::clone(&node);
                let cfg = Arc::clone(&cfg);
                let cg = Arc::clone(&conns);
                let ipc = Arc::clone(&per_ip);
                std::thread::spawn(move || {
                    let Some(_ticket) = cg.try_acquire() else {
                        return;
                    };
                    let ip = s.peer_addr().map(|p| p.ip()).ok();
                    let _ip_ticket = match ip {
                        Some(ip) => match ipc.try_acquire(ip) {
                            Some(t) => Some(t),
                            None => return,
                        },
                        None => None,
                    };
                    let conn = NEXT_CONN.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = handle(node.clone(), s, cfg, ip, conn) {
                        if !e.is_empty() {
                            eprintln!("[ws] connection closed: {}", e);
                        }
                    }
                    node.events.drop_conn(conn);
                });
            }
            Err(e) => eprintln!("[ws] accept error: {}", e),
        }
    }
    Ok(())
}

fn handle(
    node: Arc<Node>,
    mut stream: TcpStream,
    cfg: Arc<RpcConfig>,
    peer_ip: Option<IpAddr>,
    conn: u64,
) -> Result<(), String> {
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

    // ---- handshake ----
    let head = read_head(&mut stream)?;
    let mut key = None;
    let mut credential: Option<String> = None;
    let mut forwarded: Option<IpAddr> = None;
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("").to_string();
    for line in lines {
        let lower = line.to_ascii_lowercase();
        let raw = || {
            line[line.find(':').map(|i| i + 1).unwrap_or(0)..]
                .trim()
                .to_string()
        };
        if lower.starts_with("sec-websocket-key:") {
            key = Some(raw());
        } else if lower.starts_with("authorization:") {
            let v = raw();
            let t = v
                .strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
                .unwrap_or(&v)
                .to_string();
            if !t.is_empty() {
                credential = Some(t);
            }
        } else if lower.starts_with("x-api-key:") {
            let v = raw();
            if !v.is_empty() {
                credential = Some(v);
            }
        } else if lower.starts_with("x-forwarded-for:") && cfg.trust_proxy {
            forwarded = raw().split(',').next().and_then(|s| s.trim().parse().ok());
        }
    }
    // Browsers cannot set headers on a WebSocket, so a key may also arrive in the
    // query string. Same credential, same tier, same limits.
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();
    if credential.is_none() {
        if let Some(q) = path.split_once('?').map(|(_, q)| q) {
            for part in q.split('&') {
                if let Some(v) = part
                    .strip_prefix("key=")
                    .or_else(|| part.strip_prefix("apikey="))
                {
                    if !v.is_empty() {
                        credential = Some(v.to_string());
                    }
                }
            }
        }
    }
    let Some(key) = key else {
        let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
        return Err("not a websocket upgrade".into());
    };

    let tier = cfg.tier_for(credential.as_deref());
    if cfg.require_auth && tier == Tier::Anonymous {
        let _ = stream.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n");
        return Err("api key required".into());
    }
    let client_ip = forwarded
        .or(peer_ip)
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

    let accept = b64(&sha1(format!("{}{}", key.trim(), WS_GUID).as_bytes()));
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        accept
    );
    stream
        .write_all(resp.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.flush().ok();

    // ---- connection state ----
    let (sub_sender, sub_rx) = events::queue();
    let writer = Arc::new(Mutex::new(stream.try_clone().map_err(|e| e.to_string())?));
    let stop = Arc::new(AtomicBool::new(false));

    // Pump: subscription frames plus keepalive pings, independent of reads.
    let pump_writer = Arc::clone(&writer);
    let pump_stop = Arc::clone(&stop);
    let pump = std::thread::spawn(move || {
        while !pump_stop.load(Ordering::Relaxed) {
            match sub_rx.recv_timeout(PING_EVERY) {
                Ok(frame) => {
                    if send(&pump_writer, 0x1, frame.as_bytes()).is_err() {
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if send(&pump_writer, 0x9, b"inaz").is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        pump_stop.store(true, Ordering::Relaxed);
        let _ = pump_writer
            .lock()
            .unwrap()
            .shutdown(std::net::Shutdown::Both);
    });

    let mut last_seen = Instant::now();
    let mut fragment: Vec<u8> = Vec::new();
    let result = loop {
        if stop.load(Ordering::Relaxed) {
            break Ok(());
        }
        match read_frame(&mut stream) {
            Ok(Some(Frame {
                opcode,
                payload,
                fin,
            })) => {
                last_seen = Instant::now();
                match opcode {
                    0x8 => break Ok(()), // close
                    0x9 => {
                        let _ = send(&writer, 0xA, &payload); // ping -> pong
                        continue;
                    }
                    0xA => continue, // pong
                    0x2 => break Err("binary frames are not accepted".into()),
                    0x0 | 0x1 => {
                        fragment.extend_from_slice(&payload);
                        if fragment.len() > MAX_FRAME_BYTES {
                            break Err("message too large".into());
                        }
                        if !fin {
                            continue;
                        }
                        let text = std::mem::take(&mut fragment);
                        let out = handle_message(
                            &node,
                            &text,
                            &cfg,
                            tier,
                            credential.as_deref(),
                            client_ip,
                            conn,
                            &sub_sender,
                        );
                        if let Some(reply) = out {
                            if send(&writer, 0x1, reply.as_bytes()).is_err() {
                                break Ok(());
                            }
                        }
                    }
                    _ => break Err("unsupported frame".into()),
                }
            }
            Ok(None) => {
                if last_seen.elapsed() > IDLE_TIMEOUT {
                    break Err("idle timeout".into());
                }
            }
            Err(e) => break Err(e),
        }
    };

    stop.store(true, Ordering::Relaxed);
    let _ = stream.shutdown(std::net::Shutdown::Both);
    let _ = pump.join();
    node.events.drop_conn(conn);
    result
}

fn handle_message(
    node: &Arc<Node>,
    text: &[u8],
    cfg: &Arc<RpcConfig>,
    tier: Tier,
    credential: Option<&str>,
    ip: IpAddr,
    conn: u64,
    sender: &SubSender,
) -> Option<String> {
    let req: Value = match serde_json::from_slice(text) {
        Ok(v) => v,
        Err(_) => {
            return Some(
                json!({ "jsonrpc": "2.0", "id": Value::Null, "error": { "code": -32700, "message": "invalid json" } })
                    .to_string(),
            )
        }
    };
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    let params = req.get("params").cloned().unwrap_or(json!({}));

    let cost = rpcauth::method_cost(&method, &params);
    if !cfg.charge_weighted(&node.store, ip, tier, credential, cost) {
        return Some(
            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32005, "message": "rate limited" } })
                .to_string(),
        );
    }
    // Fail closed, exactly like the HTTP path: no admin key configured means the
    // operator-only methods are unavailable, not public.
    if rpcauth::PRIVILEGED_METHODS.contains(&method.as_str()) && tier != Tier::Admin {
        return Some(
            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32002, "message": "admin key required" } })
                .to_string(),
        );
    }

    let result = match method.as_str() {
        "inaz_subscribe" => {
            let channel = params
                .get("channel")
                .and_then(|v| v.as_str())
                .unwrap_or("heads")
                .to_string();
            Channel::parse(&channel, &params)
                .and_then(|c| node.events.subscribe(conn, c, sender))
                .map(|id| json!({ "subscription": id, "channel": channel, "maxPerConnection": MAX_SUBS_PER_CONN }))
        }
        "inaz_unsubscribe" => {
            let sub = params.get("subscription").and_then(|v| v.as_u64());
            match sub {
                Some(s) => Ok(json!({ "unsubscribed": node.events.unsubscribe(conn, s) })),
                None => Err("subscription id required".into()),
            }
        }
        "inaz_subscriptions" => Ok(json!({ "live": node.events.len() })),
        _ => rpc::dispatch_metered(node, &method, &params, cfg, tier),
    };

    Some(match result {
        Ok(value) => json!({ "jsonrpc": "2.0", "id": id, "result": value }).to_string(),
        Err(msg) => {
            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": msg } })
                .to_string()
        }
    })
}

// ---------------------------------------------------------------- framing

struct Frame {
    opcode: u8,
    payload: Vec<u8>,
    fin: bool,
}

fn read_exact(stream: &mut TcpStream, n: usize) -> Result<Option<Vec<u8>>, String> {
    let mut buf = vec![0u8; n];
    let mut filled = 0;
    while filled < n {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Err(String::new()), // peer closed
            Ok(r) => filled += r,
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                if filled == 0 {
                    return Ok(None); // nothing started: caller may idle-check
                }
                continue; // mid-frame: keep waiting for the rest
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(Some(buf))
}

fn read_frame(stream: &mut TcpStream) -> Result<Option<Frame>, String> {
    let Some(head) = read_exact(stream, 2)? else {
        return Ok(None);
    };
    let fin = head[0] & 0x80 != 0;
    let opcode = head[0] & 0x0F;
    let masked = head[1] & 0x80 != 0;
    let len7 = (head[1] & 0x7F) as usize;
    let len = match len7 {
        126 => {
            let b = read_exact(stream, 2)?.ok_or_else(String::new)?;
            u16::from_be_bytes([b[0], b[1]]) as usize
        }
        127 => {
            let b = read_exact(stream, 8)?.ok_or_else(String::new)?;
            let mut v = [0u8; 8];
            v.copy_from_slice(&b);
            u64::from_be_bytes(v) as usize
        }
        n => n,
    };
    if len > MAX_FRAME_BYTES {
        return Err("frame too large".into());
    }
    // RFC 6455: every client frame must be masked. An unmasked one is either a
    // broken client or a proxy-poisoning attempt; both get dropped.
    if !masked {
        return Err("client frames must be masked".into());
    }
    let mask = read_exact(stream, 4)?.ok_or_else(String::new)?;
    let mut payload = if len == 0 {
        Vec::new()
    } else {
        read_exact(stream, len)?.ok_or_else(String::new)?
    };
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= mask[i % 4];
    }
    Ok(Some(Frame {
        opcode,
        payload,
        fin,
    }))
}

fn send(stream: &Arc<Mutex<TcpStream>>, opcode: u8, payload: &[u8]) -> Result<(), String> {
    let mut out = Vec::with_capacity(payload.len() + 10);
    out.push(0x80 | opcode);
    match payload.len() {
        n if n < 126 => out.push(n as u8),
        n if n <= u16::MAX as usize => {
            out.push(126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    let mut guard = stream.lock().map_err(|_| "writer poisoned".to_string())?;
    guard.write_all(&out).map_err(|e| e.to_string())?;
    guard.flush().map_err(|e| e.to_string())
}

fn read_head(stream: &mut TcpStream) -> Result<String, String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if read == 0 {
            return Err("closed during handshake".into());
        }
        buf.extend_from_slice(&chunk[..read]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err("handshake too large".into());
        }
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

// ------------------------------------------------- handshake primitives
// SHA-1 and base64 exist here only to answer the WebSocket handshake, which the
// spec fixes to SHA-1. They are never used for anything security-bearing: chain
// hashing is SHA-256 and signatures are ed25519.

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let ml = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&ml.to_be_bytes());
    for block in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_accept_matches_the_spec_example() {
        // RFC 6455 section 1.3 worked example.
        let accept = b64(&sha1(
            format!("{}{}", "dGhlIHNhbXBsZSBub25jZQ==", WS_GUID).as_bytes(),
        ));
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn base64_pads_correctly() {
        assert_eq!(b64(b"f"), "Zg==");
        assert_eq!(b64(b"fo"), "Zm8=");
        assert_eq!(b64(b"foo"), "Zm9v");
    }
}
