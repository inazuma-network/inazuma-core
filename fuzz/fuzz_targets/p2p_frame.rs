#![no_main]
//! Length-prefix handling: a 4-byte header must never make the node reserve
//! gigabytes or wrap around. Also feeds the remainder through the body decoder
//! with the attacker-declared length, mimicking a truncated/oversized frame.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let head = [data[0], data[1], data[2], data[3]];
    match inazuma_core::transport::frame_len(&head) {
        Err(_) => {}
        Ok(n) => {
            // Declared length must stay sane; never allocate from it directly.
            assert!(n > 0 && n <= 8 * 1024 * 1024, "frame_len accepted {n}");
            let body = &data[4..];
            let take = n.min(body.len());
            let _ = inazuma_core::transport::decode_json(&body[..take]);
        }
    }
});
