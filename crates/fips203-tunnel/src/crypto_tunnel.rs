//! Handshake, session derivation, rekey (from `tunnel_main.c`).

use fips203_core::{
    decaps, encaps, frame_open, frame_seal, keygen, sha3_256, shake256, Ciphertext, EncapsKey,
    MLKEM768_CT_SIZE, MLKEM768_DK_SIZE, MLKEM768_EK_SIZE, MLKEM_SEED_SIZE, SESSION_ID_SIZE,
    TunnelSession, MAX_WIRE,
};

use crate::config::{ID_SIZE, REKEY_NONCE_SIZE, TunnelEnv};

pub const HS_TRANSCRIPT_BYTES: usize =
    2 + ID_SIZE + ID_SIZE + 32 + 32 + SESSION_ID_SIZE + MLKEM768_EK_SIZE + MLKEM768_CT_SIZE;
const MAC32_INPUT_MAX: usize = 32 + HS_TRANSCRIPT_BYTES;
pub const CTRL_MAGIC: &[u8; 4] = b"RKY1";
pub const CTRL_REQ: u8 = 1;
pub const CTRL_ACK: u8 = 2;
pub const CTRL_LEN: usize = 4 + 1 + 4 + REKEY_NONCE_SIZE;

pub struct SessionHandle {
    pub crypto: TunnelSession,
    pub rekey_waiting: bool,
    pub rekey_pending_epoch: u32,
    pub rekey_my_nonce: [u8; REKEY_NONCE_SIZE],
}

impl SessionHandle {
    pub fn new(is_client: bool, rekey_interval: u64) -> Self {
        Self {
            crypto: TunnelSession {
                is_client: if is_client { 1 } else { 0 },
                rekey_interval,
                ..TunnelSession::default()
            },
            rekey_waiting: false,
            rekey_pending_epoch: 0,
            rekey_my_nonce: [0u8; REKEY_NONCE_SIZE],
        }
    }
}

pub fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
}

pub fn random_bytes(buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(buf)
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

fn handshake_transcript(
    out: &mut [u8; HS_TRANSCRIPT_BYTES],
    cid: &[u8; ID_SIZE],
    sid_name: &[u8; ID_SIZE],
    ns: &[u8; 32],
    nc: &[u8; 32],
    session_id: &[u8; SESSION_ID_SIZE],
    ek: &EncapsKey,
    ct: &Ciphertext,
) {
    out[0] = b'C';
    out[1] = b'S';
    out[2..2 + ID_SIZE].copy_from_slice(cid);
    out[2 + ID_SIZE..2 + 2 * ID_SIZE].copy_from_slice(sid_name);
    out[2 + 2 * ID_SIZE..2 + 2 * ID_SIZE + 32].copy_from_slice(ns);
    out[2 + 2 * ID_SIZE + 32..2 + 2 * ID_SIZE + 64].copy_from_slice(nc);
    out[2 + 2 * ID_SIZE + 64..2 + 2 * ID_SIZE + 64 + SESSION_ID_SIZE].copy_from_slice(session_id);
    let o = 2 + 2 * ID_SIZE + 64 + SESSION_ID_SIZE;
    out[o..o + MLKEM768_EK_SIZE].copy_from_slice(ek);
    out[o + MLKEM768_EK_SIZE..].copy_from_slice(ct);
}

fn mac32(out: &mut [u8; 32], psk: &[u8; 32], data: &[u8]) -> bool {
    if data.len() > HS_TRANSCRIPT_BYTES {
        return false;
    }
    let mut tmp = [0u8; MAC32_INPUT_MAX];
    tmp[..32].copy_from_slice(psk);
    tmp[32..32 + data.len()].copy_from_slice(data);
    sha3_256(out, &tmp[..32 + data.len()]);
    zeroize(&mut tmp);
    true
}

pub fn derive_session(
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
    inp[112..].copy_from_slice(b"FIPS203-TUNNEL-V3");
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
    s.epoch = 0;
    s.txs = 0;
    s.rxs = 0;
    zeroize(&mut inp);
    zeroize(&mut out);
}

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

pub fn seal_frame(s: &mut TunnelSession, plain: &[u8], wire: &mut [u8]) -> std::io::Result<usize> {
    let n = frame_seal(s, plain, wire).map_err(|_| std::io::Error::other("frame_seal"))?;
    Ok(n)
}

pub fn open_frame(
    s: &mut TunnelSession,
    wire: &[u8],
    plain: &mut [u8],
) -> std::io::Result<usize> {
    frame_open(s, wire, plain).map_err(|_| std::io::Error::other("frame_open"))
}

pub async fn handshake_server(
    env: &TunnelEnv,
    rd: &mut (impl tokio::io::AsyncRead + Unpin),
    wr: &mut (impl tokio::io::AsyncWrite + Unpin),
    sess: &mut SessionHandle,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut ns = [0u8; 32];
    let mut nc = [0u8; 32];
    let mut sid = [0u8; SESSION_ID_SIZE];
    let mut seed = [0u8; MLKEM_SEED_SIZE];
    let mut ek = [0u8; MLKEM768_EK_SIZE];
    let mut dk = [0u8; MLKEM768_DK_SIZE];
    let mut ct = [0u8; MLKEM768_CT_SIZE];
    let mut ss = [0u8; 32];
    let mut ac = [0u8; 32];
    let mut as_ = [0u8; 32];
    let mut ex = [0u8; 32];
    let mut tr = [0u8; HS_TRANSCRIPT_BYTES];

    random_bytes(&mut seed)?;
    random_bytes(&mut ns)?;
    random_bytes(&mut sid)?;
    let (ek_out, dk_out) = keygen(&seed).map_err(|_| std::io::Error::other("keygen"))?;
    ek = ek_out;
    dk = dk_out;

    wr.write_all(&ns).await?;
    wr.write_all(&sid).await?;
    wr.write_all(&ek).await?;
    rd.read_exact(&mut nc).await?;
    rd.read_exact(&mut ct).await?;
    rd.read_exact(&mut ac).await?;

    let ss_out = decaps(&ct, &dk).map_err(|_| std::io::Error::other("decaps"))?;
    ss = ss_out;
    handshake_transcript(
        &mut tr,
        &env.client_id,
        &env.server_id,
        &ns,
        &nc,
        &sid,
        &ek,
        &ct,
    );
    if !mac32(&mut ex, &env.psk, &tr) || !ct_eq(&ex, &ac) {
        return Err(std::io::Error::other("handshake mac"));
    }
    if !mac32(&mut as_, &env.psk, &ss) {
        return Err(std::io::Error::other("handshake mac2"));
    }
    wr.write_all(&as_).await?;
    derive_session(&mut sess.crypto, &ss, &ns, &nc, &sid, false);
    Ok(())
}

pub async fn handshake_client(
    env: &TunnelEnv,
    rd: &mut (impl tokio::io::AsyncRead + Unpin),
    wr: &mut (impl tokio::io::AsyncWrite + Unpin),
    sess: &mut SessionHandle,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut ns = [0u8; 32];
    let mut nc = [0u8; 32];
    let mut sid = [0u8; SESSION_ID_SIZE];
    let mut m = [0u8; MLKEM_SEED_SIZE];
    let mut ek = [0u8; MLKEM768_EK_SIZE];
    let mut ct = [0u8; MLKEM768_CT_SIZE];
    let mut ss = [0u8; 32];
    let mut ac = [0u8; 32];
    let mut as_ = [0u8; 32];
    let mut ex = [0u8; 32];
    let mut tr = [0u8; HS_TRANSCRIPT_BYTES];

    random_bytes(&mut nc)?;
    random_bytes(&mut m)?;
    rd.read_exact(&mut ns).await?;
    rd.read_exact(&mut sid).await?;
    rd.read_exact(&mut ek).await?;
    let (ct_out, ss_out) = encaps(&ek, &m).map_err(|_| std::io::Error::other("encaps"))?;
    ct = ct_out;
    ss = ss_out;
    handshake_transcript(
        &mut tr,
        &env.client_id,
        &env.server_id,
        &ns,
        &nc,
        &sid,
        &ek,
        &ct,
    );
    if !mac32(&mut ac, &env.psk, &tr) {
        return Err(std::io::Error::other("handshake mac"));
    }
    wr.write_all(&nc).await?;
    wr.write_all(&ct).await?;
    wr.write_all(&ac).await?;
    rd.read_exact(&mut as_).await?;
    if !mac32(&mut ex, &env.psk, &ss) || !ct_eq(&ex, &as_) {
        return Err(std::io::Error::other("handshake verify"));
    }
    derive_session(&mut sess.crypto, &ss, &ns, &nc, &sid, true);
    Ok(())
}

pub fn wire_buf() -> [u8; MAX_WIRE] {
    [0u8; MAX_WIRE]
}
