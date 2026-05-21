//! Big-endian session blob pack/unpack (`fips203_session_pack` / `unpack`).

use crate::error::{Error, Result};
use crate::frame::{TunnelSession, SESSION_ID_SIZE, SESSION_PACKED_BYTES, SESSION_STATE_BYTES};

pub const SESSION_PACK_HEADER_U64: u64 = 0x4632_3033_5331_0001;

/// Pack session crypto state to 216 bytes (portable storage / IPC).
pub fn session_pack(session: &TunnelSession, out: &mut [u8]) -> Result<()> {
    if out.len() < SESSION_PACKED_BYTES {
        return Err(Error::BufferTooSmall);
    }
    be_store_u64(&mut out[0..8], SESSION_PACK_HEADER_U64);
    out[8..40].copy_from_slice(&session.txe);
    out[40..72].copy_from_slice(&session.txm);
    out[72..104].copy_from_slice(&session.rxe);
    out[104..136].copy_from_slice(&session.rxm);
    out[136..148].copy_from_slice(&session.txb);
    out[148..160].copy_from_slice(&session.rxb);
    be_store_u64(&mut out[160..168], session.txs);
    be_store_u64(&mut out[168..176], session.rxs);
    out[176..176 + SESSION_ID_SIZE].copy_from_slice(&session.session_id);
    be_store_u32(&mut out[192..196], session.epoch);
    be_store_u32(&mut out[196..200], session.is_client);
    be_store_u64(&mut out[200..208], session.rekey_interval);
    Ok(())
}

/// Unpack 216-byte blob into session state.
pub fn session_unpack(input: &[u8], session: &mut TunnelSession) -> Result<()> {
    if input.len() < SESSION_PACKED_BYTES {
        return Err(Error::Length);
    }
    if be_load_u64(&input[0..8]) != SESSION_PACK_HEADER_U64 {
        return Err(Error::Crypto);
    }
    session.txe.copy_from_slice(&input[8..40]);
    session.txm.copy_from_slice(&input[40..72]);
    session.rxe.copy_from_slice(&input[72..104]);
    session.rxm.copy_from_slice(&input[104..136]);
    session.txb.copy_from_slice(&input[136..148]);
    session.rxb.copy_from_slice(&input[148..160]);
    session.txs = be_load_u64(&input[160..168]);
    session.rxs = be_load_u64(&input[168..176]);
    session.session_id.copy_from_slice(&input[176..192]);
    session.epoch = be_load_u32(&input[192..196]);
    session.is_client = be_load_u32(&input[196..200]);
    session.rekey_interval = be_load_u64(&input[200..208]);
    let _ = SESSION_STATE_BYTES;
    Ok(())
}

fn be_store_u64(out: &mut [u8], v: u64) {
    for (i, b) in out.iter_mut().enumerate() {
        *b = (v >> (8 * (7 - i))) as u8;
    }
}

fn be_load_u64(input: &[u8]) -> u64 {
    let mut v = 0u64;
    for &b in input.iter().take(8) {
        v = (v << 8) | u64::from(b);
    }
    v
}

fn be_store_u32(out: &mut [u8], v: u32) {
    out[0] = (v >> 24) as u8;
    out[1] = (v >> 16) as u8;
    out[2] = (v >> 8) as u8;
    out[3] = v as u8;
}

fn be_load_u32(input: &[u8]) -> u32 {
    u32::from(input[0]) << 24
        | u32::from(input[1]) << 16
        | u32::from(input[2]) << 8
        | u32::from(input[3])
}
