#![no_main]
//! Transaction ingestion from an untrusted source: arbitrary JSON decoded into
//! the wire tx type, then canonically re-encoded. Signature verification is not
//! the point here — decoding and encoding must never panic or overflow.
use inazuma_core::types::Transaction;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(tx) = serde_json::from_slice::<Transaction>(data) {
        let _ = tx.signing_bytes();
        let _ = tx.fields_unambiguous();
        let _ = tx.canonical_signing_bytes();
        let _ = serde_json::to_vec(&tx);
    }
});
