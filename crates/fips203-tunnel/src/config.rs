//! Environment and queue limits (mirrors `tunnel_main.c`).

use std::env;

pub const ID_SIZE: usize = 32;
pub const REKEY_NONCE_SIZE: usize = 32;
pub const DEFAULT_REKEY_INTERVAL: u64 = 100_000;
pub const QUEUE_DEPTH_DEFAULT: usize = 64;
pub const QUEUE_DEPTH_HARD_MAX: usize = 4096;
pub const QUEUE_BYTES_DEFAULT: usize = 32 * 1024 * 1024;

pub struct TunnelEnv {
    pub psk: [u8; 32],
    pub client_id: [u8; ID_SIZE],
    pub server_id: [u8; ID_SIZE],
    pub rekey_interval: u64,
    pub queue_depth: usize,
    pub queue_clamped: bool,
}

pub fn load_tunnel_env() -> Result<TunnelEnv, String> {
    let psk = load_psk_hex()?;
    let client_id = load_id("TUNNEL_CLIENT_ID")?;
    let server_id = load_id("TUNNEL_SERVER_ID")?;
    let rekey_interval = load_rekey_interval();
    let (queue_depth, queue_clamped) = configure_queue_depth()?;
    Ok(TunnelEnv {
        psk,
        client_id,
        server_id,
        rekey_interval,
        queue_depth,
        queue_clamped,
    })
}

fn load_psk_hex() -> Result<[u8; 32], String> {
    let h = env::var("TUNNEL_PSK_HEX").map_err(|_| "TUNNEL_PSK_HEX not set".to_string())?;
    if h.len() != 64 {
        return Err("TUNNEL_PSK_HEX must be 64 hex chars".into());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(h.as_bytes()[2 * i])?;
        let lo = hex_nibble(h.as_bytes()[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn load_id(name: &str) -> Result<[u8; ID_SIZE], String> {
    let v = env::var(name).map_err(|_| format!("{name} not set"))?;
    if v.is_empty() || v.len() > ID_SIZE {
        return Err(format!("{name} length must be 1..={ID_SIZE}"));
    }
    let mut out = [0u8; ID_SIZE];
    out[..v.len()].copy_from_slice(v.as_bytes());
    Ok(out)
}

fn load_rekey_interval() -> u64 {
    let v = match env::var("TUNNEL_REKEY_INTERVAL") {
        Ok(s) if !s.is_empty() => s,
        _ => return DEFAULT_REKEY_INTERVAL,
    };
    v.parse::<u64>().ok().filter(|&n| n > 0).unwrap_or(DEFAULT_REKEY_INTERVAL)
}

fn configure_queue_depth() -> Result<(usize, bool), String> {
    let slot = std::mem::size_of::<u32>() + fips203_core::MAX_MSG;
    let mut want = QUEUE_DEPTH_DEFAULT;
    if let Ok(dv) = env::var("TUNNEL_QUEUE_DEPTH") {
        if !dv.is_empty() {
            if let Ok(d) = dv.parse::<usize>() {
                if (2..=QUEUE_DEPTH_HARD_MAX).contains(&d) {
                    want = d;
                }
            }
        }
    }
    let mut max_bytes = QUEUE_BYTES_DEFAULT;
    if let Ok(be) = env::var("TUNNEL_MAX_QUEUE_BYTES") {
        if !be.is_empty() {
            let v: usize = be.parse().map_err(|_| "TUNNEL_MAX_QUEUE_BYTES invalid")?;
            if v < 2 * slot {
                return Err("TUNNEL_MAX_QUEUE_BYTES too small".into());
            }
            max_bytes = v;
        }
    } else if let Ok(mb) = env::var("TUNNEL_MAX_QUEUE_MB") {
        if !mb.is_empty() {
            let m: usize = mb.parse().map_err(|_| "TUNNEL_MAX_QUEUE_MB invalid")?;
            if m == 0 || m > 1024 {
                return Err("TUNNEL_MAX_QUEUE_MB out of range".into());
            }
            max_bytes = m * 1024 * 1024;
        }
    }
    let max_depth_mem = max_bytes / slot;
    if max_depth_mem < 2 {
        return Err("queue memory budget too small".into());
    }
    let eff = want.min(max_depth_mem).min(QUEUE_DEPTH_HARD_MAX);
    let clamped = eff != want;
    Ok((eff, clamped))
}

pub fn parse_port(s: &str) -> Result<u16, String> {
    let p: u32 = s.parse().map_err(|_| "invalid port")?;
    if p == 0 || p > 65535 {
        return Err("invalid port".into());
    }
    Ok(p as u16)
}

fn hex_nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err("invalid hex".into()),
    }
}
