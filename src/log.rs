//! Ethereum-client style structured logging (the format geth/lighthouse
//! operators already know):
//!
//! ```text
//! INFO [08-19|01:23:45.123] Imported new chain segment    number=1,402,331 hash=9f2c..a1 txs=3 peers=2 elapsed=41ms
//! ```
//!
//! This is the default for `inazuma run`. The animated Inazuma HUD is still
//! available with `--ui hud` (or `INAZ_UI=hud`).

use std::io::{IsTerminal, Write};

const MSG_WIDTH: usize = 38;

const GRAY: &str = "\x1b[2m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
    Debug,
}

impl Level {
    fn tag(self) -> &'static str {
        match self {
            Level::Info => "INFO ",
            Level::Warn => "WARN ",
            Level::Error => "ERROR",
            Level::Debug => "DEBUG",
        }
    }
    fn color(self) -> &'static str {
        match self {
            Level::Info => GREEN,
            Level::Warn => YELLOW,
            Level::Error => RED,
            Level::Debug => GRAY,
        }
    }
}

fn plain() -> bool {
    std::env::var("INAZ_NO_COLOR").is_ok()
        || std::env::var("NO_COLOR").is_ok()
        || !std::io::stdout().is_terminal()
}

/// `MM-DD|HH:MM:SS.mmm` in UTC, computed without pulling in a date crate.
fn stamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let ms = now.subsec_millis();
    let secs = now.as_secs();
    let (h, mi, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    let mut days = (secs / 86_400) as i64;
    let mut year = 1970i64;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let len = if leap { 366 } else { 365 };
        if days < len {
            break;
        }
        days -= len;
        year += 1;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1;
    for len in months {
        if days < len {
            break;
        }
        days -= len;
        month += 1;
    }
    format!(
        "{:02}-{:02}|{:02}:{:02}:{:02}.{:03}",
        month,
        days + 1,
        h,
        mi,
        s,
        ms
    )
}

/// Thousands separators, the way geth prints block numbers.
pub fn num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Short `abcd..ef` hash form used in every field.
pub fn short(hash: &str) -> String {
    if hash.len() <= 10 {
        return hash.to_string();
    }
    format!("{}..{}", &hash[..8], &hash[hash.len() - 4..])
}

pub fn log(level: Level, msg: &str, kv: &[(&str, String)]) {
    let fields = kv
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join(" ");
    let out = std::io::stdout();
    let mut out = out.lock();
    let line = if plain() {
        format!(
            "{} [{}] {:<width$} {}",
            level.tag(),
            stamp(),
            msg,
            fields,
            width = MSG_WIDTH
        )
    } else {
        format!(
            "{}{}{} {}[{}]{} {:<width$} {}{}{}",
            level.color(),
            level.tag(),
            RESET,
            GRAY,
            stamp(),
            RESET,
            msg,
            GRAY,
            fields,
            RESET,
            width = MSG_WIDTH
        )
    };
    let _ = writeln!(out, "{}", line.trim_end());
}

pub fn info(msg: &str, kv: &[(&str, String)]) {
    log(Level::Info, msg, kv);
}

pub fn warn(msg: &str, kv: &[(&str, String)]) {
    log(Level::Warn, msg, kv);
}

pub fn error(msg: &str, kv: &[(&str, String)]) {
    log(Level::Error, msg, kv);
}

/// Geth's boot banner equivalent: a couple of dense lines instead of art.
pub fn welcome(version: &str, chain_id: u64, data: &str, address: &str) {
    let out = std::io::stdout();
    let mut out = out.lock();
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Inazuma/v{}/{}-{} — sovereign L1, INAZ native coin",
        version,
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let _ = writeln!(out);
    drop(out);
    info(
        "Starting Inazuma node",
        &[
            ("chain", chain_id.to_string()),
            ("datadir", data.to_string()),
            ("validator", short(address)),
        ],
    );
}
