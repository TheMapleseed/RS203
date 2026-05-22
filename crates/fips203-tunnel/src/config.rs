//! Tunnel configuration (PSK, peer IDs, queues, rekey).

use std::env;
use std::sync::Arc;

use fips203_core::tunnel::load_mlock_from_env;
use fips203_core::{
    protect_sensitive, release_sensitive, secret_zeroize,
    tunnel::{
        load_handshake_config_from_env, load_rekey_ack_timeout_secs_from_env,
        load_rekey_interval_from_env, load_wire_read_timeout_secs_from_env, HandshakeConfig,
        DEFAULT_REKEY_ACK_TIMEOUT_SECS, DEFAULT_WIRE_READ_TIMEOUT_SECS, PEER_ID_SIZE,
    },
};

pub use fips203_core::tunnel::DEFAULT_REKEY_INTERVAL;
pub const ID_SIZE: usize = PEER_ID_SIZE;
pub const REKEY_NONCE_SIZE: usize = fips203_core::REKEY_NONCE_SIZE;
pub const QUEUE_DEPTH_DEFAULT: usize = 64;
pub const QUEUE_DEPTH_HARD_MAX: usize = 4096;
pub const QUEUE_BYTES_DEFAULT: usize = 32 * 1024 * 1024;

#[derive(Debug)]
struct TunnelSecrets {
    psk: [u8; 32],
    client_id: [u8; ID_SIZE],
    server_id: [u8; ID_SIZE],
    rekey_interval: u64,
    rekey_ack_timeout_secs: u64,
    wire_read_timeout_secs: u64,
    queue_depth: usize,
    queue_clamped: bool,
    mlock_psk: bool,
}

impl Drop for TunnelSecrets {
    fn drop(&mut self) {
        if self.mlock_psk {
            release_sensitive(&mut self.psk);
        } else {
            secret_zeroize(&mut self.psk);
        }
    }
}

/// Runtime configuration for `fips203_tunnel` client/server/link.
///
/// `Clone` shares one `Arc` — the PSK is not copied into a second buffer.
#[derive(Clone, Debug)]
pub struct TunnelConfig {
    inner: Arc<TunnelSecrets>,
}

impl TunnelConfig {
    pub fn new(psk: [u8; 32], client_id: [u8; ID_SIZE], server_id: [u8; ID_SIZE]) -> Self {
        Self::from_parts(psk, client_id, server_id, DEFAULT_REKEY_INTERVAL, false)
    }

    fn from_parts(
        mut psk: [u8; 32],
        client_id: [u8; ID_SIZE],
        server_id: [u8; ID_SIZE],
        rekey_interval: u64,
        mlock_psk: bool,
    ) -> Self {
        if mlock_psk {
            protect_sensitive(&mut psk, true);
        }
        Self {
            inner: Arc::new(TunnelSecrets {
                psk,
                client_id,
                server_id,
                rekey_interval,
                rekey_ack_timeout_secs: DEFAULT_REKEY_ACK_TIMEOUT_SECS,
                wire_read_timeout_secs: DEFAULT_WIRE_READ_TIMEOUT_SECS,
                queue_depth: QUEUE_DEPTH_DEFAULT,
                queue_clamped: false,
                mlock_psk,
            }),
        }
    }

    pub fn psk(&self) -> &[u8; 32] {
        &self.inner.psk
    }

    pub fn client_id(&self) -> &[u8; ID_SIZE] {
        &self.inner.client_id
    }

    pub fn server_id(&self) -> &[u8; ID_SIZE] {
        &self.inner.server_id
    }

    pub fn rekey_interval(&self) -> u64 {
        self.inner.rekey_interval
    }

    pub fn rekey_ack_timeout_secs(&self) -> u64 {
        self.inner.rekey_ack_timeout_secs
    }

    pub fn wire_read_timeout_secs(&self) -> u64 {
        self.inner.wire_read_timeout_secs
    }

    pub fn queue_depth(&self) -> usize {
        self.inner.queue_depth
    }

    pub fn queue_clamped(&self) -> bool {
        self.inner.queue_clamped
    }

    pub fn handshake(&self) -> HandshakeConfig {
        HandshakeConfig {
            psk: self.inner.psk,
            client_id: self.inner.client_id,
            server_id: self.inner.server_id,
        }
    }

    /// Update when this is the only outstanding `Arc` (typical in tests).
    pub fn set_rekey_interval(&mut self, n: u64) {
        if let Some(s) = Arc::get_mut(&mut self.inner) {
            s.rekey_interval = n;
        }
    }
}

/// Load from `TUNNEL_PSK_HEX`, `TUNNEL_CLIENT_ID`, `TUNNEL_SERVER_ID`, queue/rekey env vars.
pub fn from_env() -> Result<TunnelConfig, String> {
    let hs = load_handshake_config_from_env().map_err(|_| "handshake env vars invalid".to_string())?;
    let rekey_interval = load_rekey_interval_from_env();
    let rekey_ack_timeout_secs = load_rekey_ack_timeout_secs_from_env();
    let wire_read_timeout_secs = load_wire_read_timeout_secs_from_env();
    let mlock_psk = load_mlock_from_env();
    let (queue_depth, queue_clamped) = configure_queue_depth()?;
    let mut cfg = TunnelConfig::from_parts(
        hs.psk,
        hs.client_id,
        hs.server_id,
        rekey_interval,
        mlock_psk,
    );
    Arc::get_mut(&mut cfg.inner)
        .expect("unique config")
        .rekey_ack_timeout_secs = rekey_ack_timeout_secs;
    Arc::get_mut(&mut cfg.inner)
        .expect("unique config")
        .wire_read_timeout_secs = wire_read_timeout_secs;
    Arc::get_mut(&mut cfg.inner)
        .expect("unique config")
        .queue_depth = queue_depth;
    Arc::get_mut(&mut cfg.inner)
        .expect("unique config")
        .queue_clamped = queue_clamped;
    Ok(cfg)
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
