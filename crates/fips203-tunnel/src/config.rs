//! Tunnel configuration (PSK, peer IDs, queues, rekey).

use std::env;

use fips203_core::tunnel::{
    load_handshake_config_from_env, load_rekey_interval_from_env, HandshakeConfig, PEER_ID_SIZE,
};

pub use fips203_core::tunnel::DEFAULT_REKEY_INTERVAL;
pub const ID_SIZE: usize = PEER_ID_SIZE;
pub const REKEY_NONCE_SIZE: usize = fips203_core::REKEY_NONCE_SIZE;
pub const QUEUE_DEPTH_DEFAULT: usize = 64;
pub const QUEUE_DEPTH_HARD_MAX: usize = 4096;
pub const QUEUE_BYTES_DEFAULT: usize = 32 * 1024 * 1024;

/// Runtime configuration for `fips203_tunnel` client/server/link.
#[derive(Clone, Debug)]
pub struct TunnelConfig {
    pub psk: [u8; 32],
    pub client_id: [u8; ID_SIZE],
    pub server_id: [u8; ID_SIZE],
    pub rekey_interval: u64,
    pub queue_depth: usize,
    pub queue_clamped: bool,
}

impl TunnelConfig {
    pub fn new(psk: [u8; 32], client_id: [u8; ID_SIZE], server_id: [u8; ID_SIZE]) -> Self {
        Self {
            psk,
            client_id,
            server_id,
            rekey_interval: DEFAULT_REKEY_INTERVAL,
            queue_depth: QUEUE_DEPTH_DEFAULT,
            queue_clamped: false,
        }
    }

    pub fn handshake(&self) -> HandshakeConfig {
        HandshakeConfig {
            psk: self.psk,
            client_id: self.client_id,
            server_id: self.server_id,
        }
    }
}

/// Load from `TUNNEL_PSK_HEX`, `TUNNEL_CLIENT_ID`, `TUNNEL_SERVER_ID`, queue/rekey env vars.
pub fn from_env() -> Result<TunnelConfig, String> {
    let hs = load_handshake_config_from_env().map_err(|_| "handshake env vars invalid".to_string())?;
    let rekey_interval = load_rekey_interval_from_env();
    let (queue_depth, queue_clamped) = configure_queue_depth()?;
    Ok(TunnelConfig {
        psk: hs.psk,
        client_id: hs.client_id,
        server_id: hs.server_id,
        rekey_interval,
        queue_depth,
        queue_clamped,
    })
}

/// Back-compat alias used internally by the binary.
pub type TunnelEnv = TunnelConfig;

pub fn load_tunnel_env() -> Result<TunnelEnv, String> {
    from_env()
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
