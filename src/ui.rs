//! Terminal UI for the node: animated brand banner, a boxed status panel and a
//! one-line live heartbeat. Pure stdout, no dependencies, degrades to plain text
//! when the output is not a TTY (`INAZ_NO_COLOR=1` forces plain).

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicU64, Ordering};

pub const DASHBOARD: &str = "https://inazuma.network/validators";

const MAGENTA: &str = "\x1b[38;5;198m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const GREEN: &str = "\x1b[38;5;120m";
const RESET: &str = "\x1b[0m";

fn plain() -> bool {
    std::env::var("INAZ_NO_COLOR").is_ok()
        || std::env::var("NO_COLOR").is_ok()
        || !std::io::stdout().is_terminal()
}

fn c(code: &str) -> &str {
    if plain() {
        ""
    } else {
        code
    }
}

const WORDMARK: [&str; 6] = [
    "  ___ _  _   _   ____  _   _ __  __   _    ",
    " |_ _| \\| | / \\ |_  / | | | |  \\/  | / \\   ",
    "  | || .` |/ _ \\ / /  | |_| | |\\/| |/ _ \\  ",
    " |___|_|\\_/_/ \\_\\/___| \\___/|_|  |_/_/ \\_\\ ",
    "                                           ",
    "   s o v e r e i g n   L 1   ·   I N A Z    ",
];

/// Animated wordmark. Each row wipes in, so the operator can see the node is
/// theirs and alive before any log noise arrives.
pub fn banner() {
    let out = std::io::stdout();
    let mut out = out.lock();
    let _ = writeln!(out);
    for (i, row) in WORDMARK.iter().enumerate() {
        let color = if i >= 4 { c(DIM) } else { c(MAGENTA) };
        if plain() {
            let _ = writeln!(out, "{}", row);
            continue;
        }
        let chars: Vec<char> = row.chars().collect();
        for step in (0..=chars.len()).step_by(6) {
            let shown: String = chars[..step].iter().collect();
            let _ = write!(out, "\r{}{}{}", color, shown, RESET);
            let _ = out.flush();
            std::thread::sleep(std::time::Duration::from_millis(8));
        }
        let _ = writeln!(out, "\r{}{}{}", color, row, RESET);
    }
    let _ = writeln!(out);
}

/// A boxed key/value panel. Values that matter are highlighted.
pub fn panel(title: &str, rows: &[(String, String)]) {
    let width: usize = 62;
    println!(
        "{}┌─ {} {}┐{}",
        c(MAGENTA),
        title,
        "─".repeat(width.saturating_sub(title.len() + 5)),
        c(RESET)
    );
    for (k, v) in rows {
        println!(
            "{}│{} {}{:<13}{} {}",
            c(MAGENTA),
            c(RESET),
            c(DIM),
            k,
            c(RESET),
            v
        );
    }
    println!(
        "{}└{}┘{}",
        c(MAGENTA),
        "─".repeat(width.saturating_sub(1)),
        c(RESET)
    );
}

/// The clickable line every operator asks for: open my validator page.
pub fn dashboard_link(address: &str) {
    let url = format!("{}?node={}", DASHBOARD, address);
    println!();
    println!(
        "  {}{}Your validator dashboard{}",
        c(BOLD),
        c(MAGENTA),
        c(RESET)
    );
    println!("  {}{}{}", c(GREEN), url, c(RESET));
    println!(
        "  {}cmd+click (macOS) or ctrl+click to open it in your browser{}",
        c(DIM),
        c(RESET)
    );
    println!();
    qr(&url);
}

/// Terminal QR of the dashboard link, so the operator can open their node page
/// on a phone without typing the address out.
pub fn qr(url: &str) {
    if plain() {
        return;
    }
    if let Ok(code) = qrcode::QrCode::with_error_correction_level(url, qrcode::EcLevel::L) {
        let rendered = code
            .render::<qrcode::render::unicode::Dense1x2>()
            .quiet_zone(true)
            .module_dimensions(1, 1)
            .build();
        for line in rendered.lines() {
            println!("  {}", line);
        }
        println!(
            "  {}scan to open your validator page on your phone{}",
            c(DIM),
            c(RESET)
        );
        println!();
    }
}

/// State of the node as the heartbeat sees it.
pub struct Beat {
    pub height: u64,
    pub target: u64,
    pub peers: usize,
    pub finalized: u64,
    pub staked: u128,
    pub validating: bool,
    pub jailed: bool,
}

fn bar(pct: f64) -> String {
    let filled = ((pct / 100.0) * 18.0).round().clamp(0.0, 18.0) as usize;
    format!("{}{}", "█".repeat(filled), "·".repeat(18 - filled))
}

const SPIN: [&str; 4] = ["▖", "▘", "▝", "▗"];

// Sync-rate tracking for the ETA: last sample height and unix millis.
static LAST_H: AtomicU64 = AtomicU64::new(0);
static LAST_MS: AtomicU64 = AtomicU64::new(0);
static RATE_MILLI: AtomicU64 = AtomicU64::new(0); // blocks/sec * 1000, smoothed

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn human_eta(secs: u64) -> String {
    if secs == 0 {
        "done".into()
    } else if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else if secs < 86_400 {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d{:02}h", secs / 86_400, (secs % 86_400) / 3600)
    }
}

/// Blocks/sec (smoothed) and ETA to the sync target, from successive heartbeats.
fn sync_rate_eta(height: u64, target: u64) -> (f64, String) {
    let now = now_ms();
    let prev_h = LAST_H.swap(height, Ordering::Relaxed);
    let prev_ms = LAST_MS.swap(now, Ordering::Relaxed);
    if prev_ms > 0 && now > prev_ms && height >= prev_h {
        let dt = (now - prev_ms) as f64 / 1000.0;
        let inst = (height - prev_h) as f64 / dt;
        let old = RATE_MILLI.load(Ordering::Relaxed) as f64 / 1000.0;
        // Exponential smoothing keeps the ETA readable instead of jittering.
        let smoothed = if old > 0.0 { old * 0.7 + inst * 0.3 } else { inst };
        RATE_MILLI.store((smoothed * 1000.0) as u64, Ordering::Relaxed);
    }
    let rate = RATE_MILLI.load(Ordering::Relaxed) as f64 / 1000.0;
    let remaining = target.saturating_sub(height);
    let eta = if remaining == 0 {
        "done".to_string()
    } else if rate > 0.05 {
        human_eta((remaining as f64 / rate).round() as u64)
    } else {
        "--".to_string()
    };
    (rate, eta)
}

/// One rewritten line: sync progress, peers, and what the node is doing right
/// now. Called on a timer from the block loop.
pub fn heartbeat(tick: usize, b: &Beat, staked_fmt: &str) {
    let target = b.target.max(b.height).max(1);
    let pct = (b.height as f64 / target as f64) * 100.0;
    let (rate, eta) = sync_rate_eta(b.height, target);
    let state = if b.jailed {
        "JAILED — will auto-rejoin"
    } else if b.peers == 0 {
        "waiting for peers"
    } else if pct < 99.5 {
        "syncing"
    } else if b.validating {
        "VALIDATING — producing blocks"
    } else if b.staked > 0 {
        "staked, joining active set"
    } else {
        "synced — stake to validate"
    };
    let line = format!(
        "{} {} {:>5.1}%  height {}/{}  final {}  {:>5.1} blk/s  eta {}  peers {}  staked {}  {}",
        SPIN[tick % 4],
        bar(pct),
        pct,
        b.height,
        target,
        b.finalized,
        rate,
        eta,
        b.peers,
        staked_fmt,
        state
    );
    if plain() {
        println!("{}", line);
    } else {
        print!("\r\x1b[2K{}{}{}", c(MAGENTA), line, c(RESET));
        let _ = std::io::stdout().flush();
    }
}

/// Next-step hints printed once at boot so nobody has to read docs mid-run.
pub fn next_steps(address: &str, staked: bool) {
    println!("  {}Next steps{}", c(BOLD), c(RESET));
    if !staked {
        println!(
            "   1. fund {} (faucet: https://inazuma.network/faucet)",
            address
        );
        println!("   2. wait for 100% sync below");
        println!("   3. in a second terminal: inazuma stake --amount 1000");
    } else {
        println!("   • inazuma stake   --amount N     add stake");
        println!("   • inazuma unstake --amount N     unbond part of your stake");
        println!("   • inazuma exit                   unbond everything and leave the set");
    }
    println!();
}

/// A one-glance table: wallet, stake, rewards/points and jail status. Printed at
/// boot and by `inazuma wallet`, so the operator never has to parse RPC JSON.
pub struct StatusRow {
    pub label: &'static str,
    pub value: String,
    pub good: Option<bool>,
}

pub fn status_table(rows: &[StatusRow]) {
    let width: usize = 62;
    println!(
        "{}┌─ status {}┐{}",
        c(MAGENTA),
        "─".repeat(width.saturating_sub(12)),
        c(RESET)
    );
    for r in rows {
        let mark = match r.good {
            Some(true) => format!("{}●{}", c(GREEN), c(RESET)),
            Some(false) => format!("{}●{}", c(MAGENTA), c(RESET)),
            None => format!("{}·{}", c(DIM), c(RESET)),
        };
        println!(
            "{}│{} {} {}{:<16}{} {}",
            c(MAGENTA),
            c(RESET),
            mark,
            c(DIM),
            r.label,
            c(RESET),
            r.value
        );
    }
    println!(
        "{}└{}┘{}",
        c(MAGENTA),
        "─".repeat(width.saturating_sub(1)),
        c(RESET)
    );
    println!();
}

/// Copy-paste command cheatsheet, so stake management needs no docs lookup.
pub fn commands(staked: bool) {
    println!("  {}{}Commands — copy & paste{}", c(BOLD), c(MAGENTA), c(RESET));
    let list: &[(&str, &str)] = if staked {
        &[
            ("inazuma wallet", "address, balance, stake, points"),
            ("inazuma stake   --amount 1000", "add stake"),
            ("inazuma unstake --amount 1000", "unbond part of your stake"),
            ("inazuma exit", "unbond everything, leave the validator set"),
            ("inazuma status", "chain height, peers, validator set"),
        ]
    } else {
        &[
            ("inazuma wallet", "address, balance, stake, points"),
            ("inazuma wallet-new", "create a fresh validator wallet"),
            ("inazuma wallet-import --key <hex>", "import an existing wallet"),
            ("inazuma stake --amount 1000", "join the validator set (min 1000 INAZ)"),
            ("inazuma status", "chain height, peers, validator set"),
        ]
    };
    for (cmd, what) in list {
        println!(
            "   {}{:<34}{} {}{}{}",
            c(GREEN),
            cmd,
            c(RESET),
            c(DIM),
            what,
            c(RESET)
        );
    }
    println!();
}
