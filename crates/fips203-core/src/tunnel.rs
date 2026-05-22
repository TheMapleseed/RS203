//! FIPS203 tunnel protocol (PSK + ML-KEM handshake, rekey control, record layer helpers).
//! Pure `std` — use from any runtime; the `fips203-tunnel` crate is only a Tokio CLI.

use std::env;
use std::io::{self, Read, Write};

use crate::error::{Error, Result};
use crate::fips202::sha3_256;
use crate::frame::{
    derive_tunnel_session, frame_open, frame_seal, rekey_apply as frame_rekey_apply, TunnelSession,
    MAX_WIRE, REKEY_NONCE_SIZE, SESSION_ID_SIZE,
};
use crate::mlkem::{
    decaps, encaps, keygen, Ciphertext, EncapsKey, MLKEM768_CT_SIZE, MLKEM768_DK_SIZE,
    MLKEM768_EK_SIZE, MLKEM_SEED_SIZE,
};
use crate::secrets::secret_zeroize;

pub const PEER_ID_SIZE: usize = 32;
pub const DEFAULT_REKEY_INTERVAL: u64 = 100_000;
/// Seconds to wait for a rekey ACK before failing the client send path.
pub const DEFAULT_REKEY_ACK_TIMEOUT_SECS: u64 = 30;
/// Per-read timeout while waiting for the next wire frame (0 = disabled).
pub const DEFAULT_WIRE_READ_TIMEOUT_SECS: u64 = 300;
/// Consecutive decrypt failures before tearing down the recv loop.
pub const MAX_DECRYPT_FAILURES: u32 = 16;
pub const HS_TRANSCRIPT_BYTES: usize =
    2 + PEER_ID_SIZE + PEER_ID_SIZE + 32 + 32 + SESSION_ID_SIZE + MLKEM768_EK_SIZE + MLKEM768_CT_SIZE;
const MAC32_INPUT_MAX: usize = 32 + HS_TRANSCRIPT_BYTES;

pub const CTRL_MAGIC: &[u8; 4] = b"RKY1";
pub const CTRL_REQ: u8 = 1;
pub const CTRL_ACK: u8 = 2;
pub const CTRL_LEN: usize = 4 + 1 + 4 + REKEY_NONCE_SIZE;

/// PSK + peer labels for handshake transcript MACs (`TUNNEL_PSK_HEX`, `TUNNEL_*_ID`).
#[derive(Debug)]
pub struct HandshakeConfig {
    pub psk: [u8; 32],
    pub client_id: [u8; PEER_ID_SIZE],
    pub server_id: [u8; PEER_ID_SIZE],
}

impl Drop for HandshakeConfig {
    fn drop(&mut self) {
        secret_zeroize(&mut self.psk);
    }
}

/// Live session plus in-band rekey state (C `S` minus pthread/TCP).
#[derive(Debug)]
pub struct TunnelRuntime {
    pub session: TunnelSession,
    pub rekey_waiting: bool,
    pub rekey_pending_epoch: u32,
    pub rekey_my_nonce: [u8; REKEY_NONCE_SIZE],
    /// Incremented on each completed rekey (audit when using `tunnel-debug` on the CLI).
    pub rekey_count: u64,
}

impl TunnelRuntime {
    pub fn new(is_client: bool, rekey_interval: u64) -> Self {
        Self {
            session: TunnelSession {
                is_client: if is_client { 1 } else { 0 },
                rekey_interval,
                ..TunnelSession::default()
            },
            rekey_waiting: false,
            rekey_pending_epoch: 0,
            rekey_my_nonce: [0u8; REKEY_NONCE_SIZE],
            rekey_count: 0,
        }
    }
}

impl Drop for TunnelRuntime {
    fn drop(&mut self) {
        secret_zeroize(&mut self.rekey_my_nonce);
    }
}

/// Constant-time compare for 32-byte MACs.
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    ct_eq(a, b)
}

pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    let mut f = std::fs::File::open("/dev/urandom").map_err(|_| Error::Crypto)?;
    f.read_exact(buf).map_err(|_| Error::Crypto)
}

/// Best-effort wipe (see [`crate::secret_zeroize`]).
pub fn zeroize(buf: &mut [u8]) {
    secret_zeroize(buf);
}

struct ServerHsBuf {
    ns: [u8; 32],
    nc: [u8; 32],
    sid: [u8; SESSION_ID_SIZE],
    seed: [u8; MLKEM_SEED_SIZE],
    ek: [u8; MLKEM768_EK_SIZE],
    dk: [u8; MLKEM768_DK_SIZE],
    ct: [u8; MLKEM768_CT_SIZE],
    ac: [u8; 32],
    as_: [u8; 32],
    ex: [u8; 32],
    tr: [u8; HS_TRANSCRIPT_BYTES],
    ss: [u8; 32],
}

impl Drop for ServerHsBuf {
    fn drop(&mut self) {
        secret_zeroize(&mut self.ns);
        secret_zeroize(&mut self.nc);
        secret_zeroize(&mut self.sid);
        secret_zeroize(&mut self.seed);
        secret_zeroize(&mut self.ek);
        secret_zeroize(&mut self.dk);
        secret_zeroize(&mut self.ct);
        secret_zeroize(&mut self.ac);
        secret_zeroize(&mut self.as_);
        secret_zeroize(&mut self.ex);
        secret_zeroize(&mut self.tr);
        secret_zeroize(&mut self.ss);
    }
}

struct ClientHsBuf {
    ns: [u8; 32],
    nc: [u8; 32],
    sid: [u8; SESSION_ID_SIZE],
    m: [u8; MLKEM_SEED_SIZE],
    ek: [u8; MLKEM768_EK_SIZE],
    ct: [u8; MLKEM768_CT_SIZE],
    ac: [u8; 32],
    as_: [u8; 32],
    ex: [u8; 32],
    tr: [u8; HS_TRANSCRIPT_BYTES],
    ss: [u8; 32],
}

impl Drop for ClientHsBuf {
    fn drop(&mut self) {
        secret_zeroize(&mut self.ns);
        secret_zeroize(&mut self.nc);
        secret_zeroize(&mut self.sid);
        secret_zeroize(&mut self.m);
        secret_zeroize(&mut self.ek);
        secret_zeroize(&mut self.ct);
        secret_zeroize(&mut self.ac);
        secret_zeroize(&mut self.as_);
        secret_zeroize(&mut self.ex);
        secret_zeroize(&mut self.tr);
        secret_zeroize(&mut self.ss);
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

fn b32(out: &mut [u8; 4], v: u32) {
    out[0] = (v >> 24) as u8;
    out[1] = (v >> 16) as u8;
    out[2] = (v >> 8) as u8;
    out[3] = v as u8;
}

pub fn u32_be(in_: &[u8; 4]) -> u32 {
    u32::from(in_[0]) << 24
        | u32::from(in_[1]) << 16
        | u32::from(in_[2]) << 8
        | u32::from(in_[3])
}

/// Build the PSK transcript blob (`handshake_transcript_build` in C).
pub fn handshake_transcript(
    out: &mut [u8; HS_TRANSCRIPT_BYTES],
    cid: &[u8; PEER_ID_SIZE],
    sid_name: &[u8; PEER_ID_SIZE],
    ns: &[u8; 32],
    nc: &[u8; 32],
    session_id: &[u8; SESSION_ID_SIZE],
    ek: &EncapsKey,
    ct: &Ciphertext,
) {
    out[0] = b'C';
    out[1] = b'S';
    out[2..2 + PEER_ID_SIZE].copy_from_slice(cid);
    out[2 + PEER_ID_SIZE..2 + 2 * PEER_ID_SIZE].copy_from_slice(sid_name);
    out[2 + 2 * PEER_ID_SIZE..2 + 2 * PEER_ID_SIZE + 32].copy_from_slice(ns);
    out[2 + 2 * PEER_ID_SIZE + 32..2 + 2 * PEER_ID_SIZE + 64].copy_from_slice(nc);
    out[2 + 2 * PEER_ID_SIZE + 64..2 + 2 * PEER_ID_SIZE + 64 + SESSION_ID_SIZE]
        .copy_from_slice(session_id);
    let o = 2 + 2 * PEER_ID_SIZE + 64 + SESSION_ID_SIZE;
    out[o..o + MLKEM768_EK_SIZE].copy_from_slice(ek);
    out[o + MLKEM768_EK_SIZE..].copy_from_slice(ct);
}

/// SHA3-256(PSK || data), max `HS_TRANSCRIPT_BYTES` for transcript.
pub fn mac32(out: &mut [u8; 32], psk: &[u8; 32], data: &[u8]) -> Result<()> {
    if data.len() > HS_TRANSCRIPT_BYTES {
        return Err(Error::Length);
    }
    let mut tmp = [0u8; MAC32_INPUT_MAX];
    tmp[..32].copy_from_slice(psk);
    tmp[32..32 + data.len()].copy_from_slice(data);
    sha3_256(out, &tmp[..32 + data.len()]);
    secret_zeroize(&mut tmp);
    Ok(())
}

pub fn rekey_apply(
    s: &mut TunnelSession,
    new_epoch: u32,
    client_nonce: &[u8; REKEY_NONCE_SIZE],
    server_nonce: &[u8; REKEY_NONCE_SIZE],
) {
    frame_rekey_apply(s, new_epoch, client_nonce, server_nonce);
}

pub fn is_control(
    p: &[u8],
    ty: &mut u8,
    epoch: &mut u32,
    nonce: &mut [u8; REKEY_NONCE_SIZE],
) -> bool {
    if p.len() != CTRL_LEN || p[..4] != *CTRL_MAGIC {
        return false;
    }
    *ty = p[4];
    *epoch = u32_be(p[5..9].try_into().unwrap());
    nonce.copy_from_slice(&p[9..9 + REKEY_NONCE_SIZE]);
    true
}

pub fn build_control(out: &mut [u8; CTRL_LEN], ty: u8, epoch: u32, nonce: &[u8; REKEY_NONCE_SIZE]) {
    out[..4].copy_from_slice(CTRL_MAGIC);
    out[4] = ty;
    b32((&mut out[5..9]).try_into().unwrap(), epoch);
    out[9..].copy_from_slice(nonce);
}

pub fn seal_plain(session: &mut TunnelSession, plain: &[u8], wire: &mut [u8]) -> Result<usize> {
    frame_seal(session, plain, wire)
}

pub fn open_plain(session: &mut TunnelSession, wire: &[u8], plain: &mut [u8]) -> Result<usize> {
    frame_open(session, wire, plain)
}

pub fn wire_buffer() -> [u8; MAX_WIRE] {
    [0u8; MAX_WIRE]
}

/// Server-side PSK + ML-KEM handshake (blocking I/O).
pub fn handshake_server(
    conn: &mut (impl Read + Write),
    cfg: &HandshakeConfig,
    runtime: &mut TunnelRuntime,
) -> io::Result<()> {
    let mut h = ServerHsBuf {
        ns: [0u8; 32],
        nc: [0u8; 32],
        sid: [0u8; SESSION_ID_SIZE],
        seed: [0u8; MLKEM_SEED_SIZE],
        ek: [0u8; MLKEM768_EK_SIZE],
        dk: [0u8; MLKEM768_DK_SIZE],
        ct: [0u8; MLKEM768_CT_SIZE],
        ac: [0u8; 32],
        as_: [0u8; 32],
        ex: [0u8; 32],
        tr: [0u8; HS_TRANSCRIPT_BYTES],
        ss: [0u8; 32],
    };

    fill_random(&mut h.seed).map_err(io_err)?;
    fill_random(&mut h.ns).map_err(io_err)?;
    fill_random(&mut h.sid).map_err(io_err)?;
    let (ek_out, dk_out) = keygen(&h.seed).map_err(io_err)?;
    h.ek = ek_out;
    h.dk = dk_out;

    conn.write_all(&h.ns)?;
    conn.write_all(&h.sid)?;
    conn.write_all(&h.ek)?;
    conn.read_exact(&mut h.nc)?;
    conn.read_exact(&mut h.ct)?;
    conn.read_exact(&mut h.ac)?;

    h.ss = decaps(&h.ct, &h.dk).map_err(io_err)?;
    handshake_transcript(
        &mut h.tr,
        &cfg.client_id,
        &cfg.server_id,
        &h.ns,
        &h.nc,
        &h.sid,
        &h.ek,
        &h.ct,
    );
    mac32(&mut h.ex, &cfg.psk, &h.tr).map_err(io_err)?;
    if !ct_eq(&h.ex, &h.ac) {
        return Err(io::Error::other("handshake mac"));
    }
    mac32(&mut h.as_, &cfg.psk, &h.ss).map_err(io_err)?;
    conn.write_all(&h.as_)?;
    derive_tunnel_session(&mut runtime.session, &h.ss, &h.ns, &h.nc, &h.sid, false);
    Ok(())
}

/// Client-side PSK + ML-KEM handshake (blocking I/O).
pub fn handshake_client(
    conn: &mut (impl Read + Write),
    cfg: &HandshakeConfig,
    runtime: &mut TunnelRuntime,
) -> io::Result<()> {
    let mut h = ClientHsBuf {
        ns: [0u8; 32],
        nc: [0u8; 32],
        sid: [0u8; SESSION_ID_SIZE],
        m: [0u8; MLKEM_SEED_SIZE],
        ek: [0u8; MLKEM768_EK_SIZE],
        ct: [0u8; MLKEM768_CT_SIZE],
        ac: [0u8; 32],
        as_: [0u8; 32],
        ex: [0u8; 32],
        tr: [0u8; HS_TRANSCRIPT_BYTES],
        ss: [0u8; 32],
    };

    fill_random(&mut h.nc).map_err(io_err)?;
    fill_random(&mut h.m).map_err(io_err)?;
    conn.read_exact(&mut h.ns)?;
    conn.read_exact(&mut h.sid)?;
    conn.read_exact(&mut h.ek)?;
    let (ct_out, ss) = encaps(&h.ek, &h.m).map_err(io_err)?;
    h.ct = ct_out;
    h.ss = ss;
    handshake_transcript(
        &mut h.tr,
        &cfg.client_id,
        &cfg.server_id,
        &h.ns,
        &h.nc,
        &h.sid,
        &h.ek,
        &h.ct,
    );
    mac32(&mut h.ac, &cfg.psk, &h.tr).map_err(io_err)?;
    conn.write_all(&h.nc)?;
    conn.write_all(&h.ct)?;
    conn.write_all(&h.ac)?;
    conn.read_exact(&mut h.as_)?;
    mac32(&mut h.ex, &cfg.psk, &h.ss).map_err(io_err)?;
    if !ct_eq(&h.ex, &h.as_) {
        return Err(io::Error::other("handshake verify"));
    }
    derive_tunnel_session(&mut runtime.session, &h.ss, &h.ns, &h.nc, &h.sid, true);
    Ok(())
}

fn io_err(_: Error) -> io::Error {
    io::Error::other("crypto")
}

/// Load PSK and peer IDs from `TUNNEL_PSK_HEX`, `TUNNEL_CLIENT_ID`, `TUNNEL_SERVER_ID`.
pub fn load_handshake_config_from_env() -> Result<HandshakeConfig> {
    let psk = load_psk_hex_env()?;
    let client_id = load_peer_id_env("TUNNEL_CLIENT_ID")?;
    let server_id = load_peer_id_env("TUNNEL_SERVER_ID")?;
    Ok(HandshakeConfig {
        psk,
        client_id,
        server_id,
    })
}

/// Read `TUNNEL_REKEY_INTERVAL` or return [`DEFAULT_REKEY_INTERVAL`].
pub fn load_rekey_interval_from_env() -> u64 {
    match env::var("TUNNEL_REKEY_INTERVAL") {
        Ok(s) if !s.is_empty() => s
            .parse::<u64>()
            .ok()
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_REKEY_INTERVAL),
        _ => DEFAULT_REKEY_INTERVAL,
    }
}

/// `TUNNEL_REKEY_ACK_TIMEOUT` seconds (default [`DEFAULT_REKEY_ACK_TIMEOUT_SECS`]).
pub fn load_rekey_ack_timeout_secs_from_env() -> u64 {
    parse_positive_env_u64("TUNNEL_REKEY_ACK_TIMEOUT", DEFAULT_REKEY_ACK_TIMEOUT_SECS)
}

/// `TUNNEL_WIRE_READ_TIMEOUT` seconds; `0` disables the read deadline.
pub fn load_wire_read_timeout_secs_from_env() -> u64 {
    match env::var("TUNNEL_WIRE_READ_TIMEOUT") {
        Ok(s) if !s.is_empty() => s.parse::<u64>().unwrap_or(DEFAULT_WIRE_READ_TIMEOUT_SECS),
        _ => DEFAULT_WIRE_READ_TIMEOUT_SECS,
    }
}

fn parse_positive_env_u64(name: &str, default: u64) -> u64 {
    match env::var(name) {
        Ok(s) if !s.is_empty() => s.parse::<u64>().ok().filter(|&n| n > 0).unwrap_or(default),
        _ => default,
    }
}

/// `TUNNEL_MLOCK=1` pins PSK (and other locked buffers) in RAM on Unix when permitted.
pub fn load_mlock_from_env() -> bool {
    match env::var("TUNNEL_MLOCK") {
        Ok(s) => matches!(s.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"),
        _ => false,
    }
}

fn load_psk_hex_env() -> Result<[u8; 32]> {
    let h = env::var("TUNNEL_PSK_HEX").map_err(|_| Error::Length)?;
    if h.len() != 64 {
        return Err(Error::Length);
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(h.as_bytes()[2 * i])?;
        let lo = hex_nibble(h.as_bytes()[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn load_peer_id_env(name: &str) -> Result<[u8; PEER_ID_SIZE]> {
    let v = env::var(name).map_err(|_| Error::Length)?;
    if v.is_empty() || v.len() > PEER_ID_SIZE {
        return Err(Error::Length);
    }
    let mut out = [0u8; PEER_ID_SIZE];
    out[..v.len()].copy_from_slice(v.as_bytes());
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::Length),
    }
}
