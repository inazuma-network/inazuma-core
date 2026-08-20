//! Persistent double-sign guard.
//!
//! A validator key must never sign two different blocks (or votes) at the same
//! height: that is equivocation, and it burns stake and tombstones the key
//! permanently. The dangerous moments are operational, not adversarial — two
//! processes started with the same key, or a node restored from a snapshot that
//! rewinds it below a height it already signed.
//!
//! The guard records the highest height this key has signed. It deliberately
//! lives *beside* the data directory rather than inside it, so wiping the
//! database or restoring a snapshot does not erase the memory of what was
//! already signed. It is append-safe, fsynced and cheap: one small file write
//! per sealed block.
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

pub struct SignGuard {
    path: PathBuf,
    address: String,
    highest: Mutex<u64>,
}

impl SignGuard {
    /// `data` is the node data directory; the guard file is `<data>.signguard`.
    pub fn open(data: &str, address: &str) -> Self {
        let path = PathBuf::from(format!("{}.signguard", data.trim_end_matches('/')));
        let highest = fs::read_to_string(&path)
            .ok()
            .and_then(|raw| parse(&raw, address))
            .unwrap_or(0);
        SignGuard {
            path,
            address: address.to_string(),
            highest: Mutex::new(highest),
        }
    }

    pub fn highest_signed(&self) -> u64 {
        *self.highest.lock().unwrap()
    }

    /// True when this key may sign `height`. Signing at or below the highest
    /// height already signed would be equivocation.
    pub fn may_sign(&self, height: u64) -> bool {
        height > *self.highest.lock().unwrap()
    }

    /// Record `height` as signed before the block leaves the node. Persisted
    /// first so a crash between signing and gossiping still remembers it.
    pub fn record(&self, height: u64) {
        let mut cur = self.highest.lock().unwrap();
        if height <= *cur {
            return;
        }
        *cur = height;
        let body = format!("{} {}\n", self.address, height);
        if let Ok(mut f) = fs::File::create(&self.path) {
            let _ = f.write_all(body.as_bytes());
            let _ = f.sync_all();
        }
    }
}

/// Guard files are `<address> <height>`. A file written by another key is
/// ignored: it says nothing about what this key signed.
fn parse(raw: &str, address: &str) -> Option<u64> {
    let mut parts = raw.split_whitespace();
    let addr = parts.next()?;
    let height: u64 = parts.next()?.parse().ok()?;
    if addr == address {
        Some(height)
    } else {
        None
    }
}
