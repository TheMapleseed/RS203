//! FIPS203TUNNEL-GCM seal/open — ported from `src/fips203_frame.c`.

use crate::error::{Error, Result};
use crate::fips202::{sha3_256, shake256};

pub const TAG: usize = 16;
pub const SESSION_ID_SIZE: usize = 16;
pub const MAX_MSG: usize = 4096;
pub const MAX_FRAMES: u64 = 1_000_000;
pub const AAD_SIZE: usize = 4 + 8 + 4 + SESSION_ID_SIZE;
pub const MAX_WIRE: usize = 32 + MAX_MSG;
const TAG_INPUT_MAX: usize = 32 + AAD_SIZE + MAX_MSG;

/// Mutable session state (`fips203_tunnel_session_core_t`, 200 bytes).
#[derive(Clone, Debug, Default)]
pub struct TunnelSession {
    pub txe: [u8; 32],
    pub txm: [u8; 32],
    pub rxe: [u8; 32],
    pub rxm: [u8; 32],
    pub txb: [u8; 12],
    pub rxb: [u8; 12],
    pub txs: u64,
    pub rxs: u64,
    pub session_id: [u8; SESSION_ID_SIZE],
    pub epoch: u32,
    /// `1` = client, `0` = server (wire direction / rekey).
    pub is_client: u32,
    pub rekey_interval: u64,
}

pub const SESSION_STATE_BYTES: usize = 200;
pub const SESSION_PACKED_BYTES: usize = 216;
pub const REKEY_NONCE_SIZE: usize = 32;

/// Post-handshake key derivation (`derive()` in `tunnel_main.c`).
pub fn derive_tunnel_session(
    s: &mut TunnelSession,
    ss: &[u8; 32],
    ns: &[u8; 32],
    nc: &[u8; 32],
    sid: &[u8; SESSION_ID_SIZE],
    init_client: bool,
) {
    let mut inp = [0u8; 128];
    inp[..32].copy_from_slice(ss);
    inp[32..64].copy_from_slice(ns);
    inp[64..96].copy_from_slice(nc);
    inp[96..112].copy_from_slice(sid);
    inp[112..128].copy_from_slice(&b"FIPS203-TUNNEL-V3"[..16]);
    let mut out = [0u8; 152];
    shake256(&mut out, &inp);
    if init_client {
        s.txe.copy_from_slice(&out[..32]);
        s.txm.copy_from_slice(&out[32..64]);
        s.rxe.copy_from_slice(&out[64..96]);
        s.rxm.copy_from_slice(&out[96..128]);
        s.txb.copy_from_slice(&out[128..140]);
        s.rxb.copy_from_slice(&out[140..152]);
    } else {
        s.rxe.copy_from_slice(&out[..32]);
        s.rxm.copy_from_slice(&out[32..64]);
        s.txe.copy_from_slice(&out[64..96]);
        s.txm.copy_from_slice(&out[96..128]);
        s.rxb.copy_from_slice(&out[128..140]);
        s.txb.copy_from_slice(&out[140..152]);
    }
    s.session_id.copy_from_slice(sid);
    s.is_client = if init_client { 1 } else { 0 };
    s.epoch = 0;
    s.txs = 0;
    s.rxs = 0;
    zeroize(&mut inp);
    zeroize(&mut out);
}

/// In-band epoch rekey (`rekey_apply` in `tunnel_main.c`).
pub fn rekey_apply(
    s: &mut TunnelSession,
    new_epoch: u32,
    client_nonce: &[u8; REKEY_NONCE_SIZE],
    server_nonce: &[u8; REKEY_NONCE_SIZE],
) {
    let mut c2s_e = [0u8; 32];
    let mut c2s_m = [0u8; 32];
    let mut s2c_e = [0u8; 32];
    let mut s2c_m = [0u8; 32];
    let mut c2s_b = [0u8; 12];
    let mut s2c_b = [0u8; 12];
    let mut inp = [0u8; 32 + 32 + 32 + 16 + 4 + REKEY_NONCE_SIZE + REKEY_NONCE_SIZE];
    let mut out = [0u8; 152];
    if s.is_client != 0 {
        inp[..32].copy_from_slice(&s.txe);
        inp[32..64].copy_from_slice(&s.txm);
        inp[64..96].copy_from_slice(&s.rxe);
    } else {
        inp[..32].copy_from_slice(&s.rxe);
        inp[32..64].copy_from_slice(&s.rxm);
        inp[64..96].copy_from_slice(&s.txe);
    }
    inp[96..112].copy_from_slice(b"FIPS203-REKEY-V1");
    let mut eb = [0u8; 4];
    b32(&mut eb, new_epoch);
    inp[112..116].copy_from_slice(&eb);
    inp[116..116 + REKEY_NONCE_SIZE].copy_from_slice(client_nonce);
    inp[148..].copy_from_slice(server_nonce);
    shake256(&mut out, &inp);
    c2s_e.copy_from_slice(&out[..32]);
    c2s_m.copy_from_slice(&out[32..64]);
    s2c_e.copy_from_slice(&out[64..96]);
    s2c_m.copy_from_slice(&out[96..128]);
    c2s_b.copy_from_slice(&out[128..140]);
    s2c_b.copy_from_slice(&out[140..152]);
    if s.is_client != 0 {
        s.txe.copy_from_slice(&c2s_e);
        s.txm.copy_from_slice(&c2s_m);
        s.rxe.copy_from_slice(&s2c_e);
        s.rxm.copy_from_slice(&s2c_m);
        s.txb.copy_from_slice(&c2s_b);
        s.rxb.copy_from_slice(&s2c_b);
    } else {
        s.rxe.copy_from_slice(&c2s_e);
        s.rxm.copy_from_slice(&c2s_m);
        s.txe.copy_from_slice(&s2c_e);
        s.txm.copy_from_slice(&s2c_m);
        s.rxb.copy_from_slice(&c2s_b);
        s.txb.copy_from_slice(&s2c_b);
    }
    s.epoch = new_epoch;
    s.txs = 0;
    s.rxs = 0;
    zeroize(&mut inp);
    zeroize(&mut out);
}

fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }
    d == 0
}

fn b64(out: &mut [u8; 8], v: u64) {
    for (i, o) in out.iter_mut().enumerate() {
        *o = (v >> (56 - 8 * i)) as u8;
    }
}

fn u64_be(in_: &[u8; 8]) -> u64 {
    let mut v = 0u64;
    for &b in in_.iter() {
        v = (v << 8) | u64::from(b);
    }
    v
}

fn u32_be(in_: &[u8; 4]) -> u32 {
    u32::from(in_[0]) << 24
        | u32::from(in_[1]) << 16
        | u32::from(in_[2]) << 8
        | u32::from(in_[3])
}

fn b32(out: &mut [u8; 4], v: u32) {
    out[0] = (v >> 24) as u8;
    out[1] = (v >> 16) as u8;
    out[2] = (v >> 8) as u8;
    out[3] = v as u8;
}

fn nonce(n: &mut [u8; 12], b: &[u8; 12], s: u64) {
    n.copy_from_slice(b);
    let mut x = [0u8; 8];
    b64(&mut x, s);
    for i in 0..8 {
        n[4 + i] ^= x[i];
    }
}

fn ks(out: &mut [u8], k: &[u8; 32], no: &[u8; 12]) {
    let mut seed = [0u8; 44];
    seed[..32].copy_from_slice(k);
    seed[32..].copy_from_slice(no);
    shake256(out, &seed);
    zeroize(&mut seed);
}

fn compute_tag(
    t: &mut [u8; 32],
    mk: &[u8; 32],
    aad: &[u8; AAD_SIZE],
    c: &[u8],
) -> Result<()> {
    if c.len() > MAX_MSG {
        return Err(Error::Length);
    }
    let mut tmp = [0u8; TAG_INPUT_MAX];
    tmp[..32].copy_from_slice(mk);
    tmp[32..32 + AAD_SIZE].copy_from_slice(aad);
    if !c.is_empty() {
        tmp[32 + AAD_SIZE..32 + AAD_SIZE + c.len()].copy_from_slice(c);
    }
    sha3_256(t, &tmp[..32 + AAD_SIZE + c.len()]);
    zeroize(&mut tmp);
    Ok(())
}

fn encrypt(
    c: &mut [u8],
    t: &mut [u8; TAG],
    ek: &[u8; 32],
    mk: &[u8; 32],
    no: &[u8; 12],
    aad: &[u8; AAD_SIZE],
    p: &[u8],
) -> Result<()> {
    let n = p.len();
    if n > 0 {
        ks(c, ek, no);
        for i in 0..n {
            c[i] ^= p[i];
        }
    }
    let mut full = [0u8; 32];
    compute_tag(&mut full, mk, aad, &c[..n])?;
    t.copy_from_slice(&full[..TAG]);
    zeroize(&mut full);
    Ok(())
}

fn decrypt(
    p: &mut [u8],
    t: &[u8; TAG],
    ek: &[u8; 32],
    mk: &[u8; 32],
    no: &[u8; 12],
    aad: &[u8; AAD_SIZE],
    c: &[u8],
) -> Result<()> {
    let n = c.len();
    let mut full = [0u8; 32];
    compute_tag(&mut full, mk, aad, c)?;
    if !ct_eq(&full[..TAG], t) {
        zeroize(&mut full);
        return Err(Error::Crypto);
    }
    zeroize(&mut full);
    if n > 0 {
        ks(p, ek, no);
        for i in 0..n {
            p[i] ^= c[i];
        }
    }
    Ok(())
}

/// Decrypt and verify one wire frame.
pub fn frame_open(
    session: &mut TunnelSession,
    wire: &[u8],
    plaintext_out: &mut [u8],
) -> Result<usize> {
    if session.rxs >= MAX_FRAMES {
        return Err(Error::Crypto);
    }
    if wire.len() < 16 + TAG {
        return Err(Error::Length);
    }
    let lb = &wire[..4];
    let sb = &wire[4..12];
    let eb = &wire[12..16];
    let n = u32_be(lb.try_into().unwrap()) as usize;
    let seq = u64_be(sb.try_into().unwrap());
    let epoch = u32_be(eb.try_into().unwrap());
    if n > MAX_MSG || wire.len() != 16 + n + TAG {
        return Err(Error::Length);
    }
    if seq != session.rxs || epoch != session.epoch {
        return Err(Error::Crypto);
    }
    let mut aad = [0u8; AAD_SIZE];
    aad[..4].copy_from_slice(lb);
    aad[4..12].copy_from_slice(sb);
    aad[12..16].copy_from_slice(eb);
    aad[16..].copy_from_slice(&session.session_id);
    let mut no = [0u8; 12];
    nonce(&mut no, &session.rxb, seq);
    let c = &wire[16..16 + n];
    let mut tg = [0u8; TAG];
    tg.copy_from_slice(&wire[16 + n..16 + n + TAG]);
    if plaintext_out.len() < n {
        return Err(Error::BufferTooSmall);
    }
    decrypt(
        &mut plaintext_out[..n],
        &tg,
        &session.rxe,
        &session.rxm,
        &no,
        &aad,
        c,
    )?;
    session.rxs += 1;
    Ok(n)
}

/// Encrypt one plaintext frame into `wire_out`.
pub fn frame_seal(
    session: &mut TunnelSession,
    plaintext: &[u8],
    wire_out: &mut [u8],
) -> Result<usize> {
    let n = plaintext.len();
    if n > MAX_MSG || session.txs >= MAX_FRAMES {
        return Err(Error::Length);
    }
    let wire_len = 16 + n + TAG;
    if wire_out.len() < wire_len {
        return Err(Error::BufferTooSmall);
    }
    let mut lb = [0u8; 4];
    let mut sb = [0u8; 8];
    let mut eb = [0u8; 4];
    b32(&mut lb, n as u32);
    b64(&mut sb, session.txs);
    b32(&mut eb, session.epoch);
    let mut aad = [0u8; AAD_SIZE];
    aad[..4].copy_from_slice(&lb);
    aad[4..12].copy_from_slice(&sb);
    aad[12..16].copy_from_slice(&eb);
    aad[16..].copy_from_slice(&session.session_id);
    let mut no = [0u8; 12];
    nonce(&mut no, &session.txb, session.txs);
    let mut c = [0u8; MAX_MSG];
    let mut tg = [0u8; TAG];
    encrypt(
        &mut c[..n],
        &mut tg,
        &session.txe,
        &session.txm,
        &no,
        &aad,
        plaintext,
    )?;
    wire_out[..4].copy_from_slice(&lb);
    wire_out[4..12].copy_from_slice(&sb);
    wire_out[12..16].copy_from_slice(&eb);
    if n > 0 {
        wire_out[16..16 + n].copy_from_slice(&c[..n]);
    }
    wire_out[16 + n..wire_len].copy_from_slice(&tg);
    session.txs += 1;
    zeroize(&mut c);
    Ok(wire_len)
}
