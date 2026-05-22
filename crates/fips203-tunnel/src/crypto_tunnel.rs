//! Async handshake over Tokio I/O (record layer in `fips203_core`).

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

pub async fn handshake_server(
    cfg: &TunnelConfig,
    rd: &mut (impl tokio::io::AsyncRead + Unpin),
    wr: &mut (impl tokio::io::AsyncWrite + Unpin),
    sess: &mut SessionHandle,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let hs = cfg.handshake();
    let mut ns = [0u8; 32];
    let mut nc = [0u8; 32];
    let mut sid = [0u8; SESSION_ID_SIZE];
    let mut seed = [0u8; MLKEM_SEED_SIZE];
    let mut ek = [0u8; MLKEM768_EK_SIZE];
    let mut dk = [0u8; MLKEM768_DK_SIZE];
    let mut ct = [0u8; MLKEM768_CT_SIZE];
    let mut ac = [0u8; 32];
    let mut as_ = [0u8; 32];
    let mut ex = [0u8; 32];
    let mut tr = [0u8; HS_TRANSCRIPT_BYTES];

    fill_random(&mut seed).map_err(std::io::Error::other)?;
    fill_random(&mut ns).map_err(std::io::Error::other)?;
    fill_random(&mut sid).map_err(std::io::Error::other)?;
    let (ek_out, dk_out) = keygen(&seed).map_err(std::io::Error::other)?;
    ek = ek_out;
    dk = dk_out;

    wr.write_all(&ns).await?;
    wr.write_all(&sid).await?;
    wr.write_all(&ek).await?;
    rd.read_exact(&mut nc).await?;
    rd.read_exact(&mut ct).await?;
    rd.read_exact(&mut ac).await?;

    let ss = decaps(&ct, &dk).map_err(std::io::Error::other)?;
    handshake_transcript(
        &mut tr,
        &hs.client_id,
        &hs.server_id,
        &ns,
        &nc,
        &sid,
        &ek,
        &ct,
    );
    mac32(&mut ex, &hs.psk, &tr).map_err(std::io::Error::other)?;
    if !ct_eq_32(&ex, &ac) {
        return Err(std::io::Error::other("handshake mac"));
    }
    mac32(&mut as_, &hs.psk, &ss).map_err(std::io::Error::other)?;
    wr.write_all(&as_).await?;
    derive_tunnel_session(&mut sess.session, &ss, &ns, &nc, &sid, false);
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
    let mut ns = [0u8; 32];
    let mut nc = [0u8; 32];
    let mut sid = [0u8; SESSION_ID_SIZE];
    let mut m = [0u8; MLKEM_SEED_SIZE];
    let mut ek = [0u8; MLKEM768_EK_SIZE];
    let mut ct = [0u8; MLKEM768_CT_SIZE];
    let mut ac = [0u8; 32];
    let mut as_ = [0u8; 32];
    let mut ex = [0u8; 32];
    let mut tr = [0u8; HS_TRANSCRIPT_BYTES];

    fill_random(&mut nc).map_err(std::io::Error::other)?;
    fill_random(&mut m).map_err(std::io::Error::other)?;
    rd.read_exact(&mut ns).await?;
    rd.read_exact(&mut sid).await?;
    rd.read_exact(&mut ek).await?;
    let (ct_out, ss) = encaps(&ek, &m).map_err(std::io::Error::other)?;
    ct = ct_out;
    handshake_transcript(
        &mut tr,
        &hs.client_id,
        &hs.server_id,
        &ns,
        &nc,
        &sid,
        &ek,
        &ct,
    );
    mac32(&mut ac, &hs.psk, &tr).map_err(std::io::Error::other)?;
    wr.write_all(&nc).await?;
    wr.write_all(&ct).await?;
    wr.write_all(&ac).await?;
    rd.read_exact(&mut as_).await?;
    mac32(&mut ex, &hs.psk, &ss).map_err(std::io::Error::other)?;
    if !ct_eq_32(&ex, &as_) {
        return Err(std::io::Error::other("handshake verify"));
    }
    derive_tunnel_session(&mut sess.session, &ss, &ns, &nc, &sid, true);
    Ok(())
}
