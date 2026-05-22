//! Async handshake over Tokio I/O (record layer in `fips203_core`).

use fips203_core::secret_zeroize;
use fips203_core::tunnel::{
    ct_eq_32, fill_random, handshake_transcript, mac32, TunnelRuntime,
};
use fips203_core::{
    decaps, derive_tunnel_session, encaps, keygen, TunnelSession, MLKEM768_CT_SIZE,
    MLKEM768_DK_SIZE, MLKEM768_EK_SIZE, MLKEM_SEED_SIZE, MAX_WIRE, SESSION_ID_SIZE,
};
use fips203_core::tunnel::{open_plain, seal_plain, wire_buffer, HS_TRANSCRIPT_BYTES};

use crate::config::TunnelConfig;

pub use fips203_core::tunnel::{
    build_control, is_control, rekey_apply, u32_be, CTRL_ACK, CTRL_LEN, CTRL_MAGIC, CTRL_REQ,
};
pub use fips203_core::REKEY_NONCE_SIZE;

pub type SessionHandle = TunnelRuntime;

pub fn seal_frame(s: &mut TunnelSession, plain: &[u8], wire: &mut [u8]) -> std::io::Result<usize> {
    seal_plain(s, plain, wire).map_err(|_| std::io::Error::other("frame_seal"))
}

pub fn open_frame(
    s: &mut TunnelSession,
    wire: &[u8],
    plain: &mut [u8],
) -> std::io::Result<usize> {
    open_plain(s, wire, plain).map_err(|_| std::io::Error::other("frame_open"))
}

pub fn wire_buf() -> [u8; MAX_WIRE] {
    wire_buffer()
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

pub async fn handshake_server(
    cfg: &TunnelConfig,
    rd: &mut (impl tokio::io::AsyncRead + Unpin),
    wr: &mut (impl tokio::io::AsyncWrite + Unpin),
    sess: &mut SessionHandle,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let hs = cfg.handshake();
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

    fill_random(&mut h.seed).map_err(std::io::Error::other)?;
    fill_random(&mut h.ns).map_err(std::io::Error::other)?;
    fill_random(&mut h.sid).map_err(std::io::Error::other)?;
    let (ek_out, dk_out) = keygen(&h.seed).map_err(std::io::Error::other)?;
    h.ek = ek_out;
    h.dk = dk_out;

    wr.write_all(&h.ns).await?;
    wr.write_all(&h.sid).await?;
    wr.write_all(&h.ek).await?;
    rd.read_exact(&mut h.nc).await?;
    rd.read_exact(&mut h.ct).await?;
    rd.read_exact(&mut h.ac).await?;

    h.ss = decaps(&h.ct, &h.dk).map_err(std::io::Error::other)?;
    handshake_transcript(
        &mut h.tr,
        &hs.client_id,
        &hs.server_id,
        &h.ns,
        &h.nc,
        &h.sid,
        &h.ek,
        &h.ct,
    );
    mac32(&mut h.ex, &hs.psk, &h.tr).map_err(std::io::Error::other)?;
    if !ct_eq_32(&h.ex, &h.ac) {
        return Err(std::io::Error::other("handshake mac"));
    }
    mac32(&mut h.as_, &hs.psk, &h.ss).map_err(std::io::Error::other)?;
    wr.write_all(&h.as_).await?;
    derive_tunnel_session(&mut sess.session, &h.ss, &h.ns, &h.nc, &h.sid, false);
    Ok(())
}

pub async fn handshake_client(
    cfg: &TunnelConfig,
    rd: &mut (impl tokio::io::AsyncRead + Unpin),
    wr: &mut (impl tokio::io::AsyncWrite + Unpin),
    sess: &mut SessionHandle,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let hs = cfg.handshake();
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

    fill_random(&mut h.nc).map_err(std::io::Error::other)?;
    fill_random(&mut h.m).map_err(std::io::Error::other)?;
    rd.read_exact(&mut h.ns).await?;
    rd.read_exact(&mut h.sid).await?;
    rd.read_exact(&mut h.ek).await?;
    let (ct_out, ss) = encaps(&h.ek, &h.m).map_err(std::io::Error::other)?;
    h.ct = ct_out;
    h.ss = ss;
    handshake_transcript(
        &mut h.tr,
        &hs.client_id,
        &hs.server_id,
        &h.ns,
        &h.nc,
        &h.sid,
        &h.ek,
        &h.ct,
    );
    mac32(&mut h.ac, &hs.psk, &h.tr).map_err(std::io::Error::other)?;
    wr.write_all(&h.nc).await?;
    wr.write_all(&h.ct).await?;
    wr.write_all(&h.ac).await?;
    rd.read_exact(&mut h.as_).await?;
    mac32(&mut h.ex, &hs.psk, &h.ss).map_err(std::io::Error::other)?;
    if !ct_eq_32(&h.ex, &h.as_) {
        return Err(std::io::Error::other("handshake verify"));
    }
    derive_tunnel_session(&mut sess.session, &h.ss, &h.ns, &h.nc, &h.sid, true);
    Ok(())
}
