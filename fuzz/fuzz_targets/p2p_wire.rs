#![no_main]
//! Malformed p2p payloads straight into the wire decoders.
//!
//! Everything reachable here is what an unauthenticated peer controls after the
//! INSC1 handshake: raw frame bodies and legacy newline JSON. Any panic, hang or
//! unbounded allocation found here is a remote DoS on every node.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Encrypted-frame body path.
    let _ = inazuma_core::transport::decode_json(data);

    // Legacy line path (only valid UTF-8 can reach it on a real socket).
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = inazuma_core::transport::decode_line(s);
        for line in s.split('\n') {
            let _ = inazuma_core::transport::decode_line(line);
        }
    }
});
