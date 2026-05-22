//! Untrusted session blobs must be rejected when counters or role are invalid.

use fips203_core::{
    session_pack, session_unpack, Error, TunnelSession, SESSION_PACKED_BYTES,
};

#[test]
fn session_unpack_rejects_max_frames_counters() {
    let mut s = TunnelSession::default();
    s.txs = fips203_core::MAX_FRAMES;
    let mut packed = [0u8; SESSION_PACKED_BYTES];
    session_pack(&s, &mut packed).unwrap();
    let mut out = TunnelSession::default();
    assert_eq!(session_unpack(&packed, &mut out), Err(Error::Crypto));
}

#[test]
fn session_unpack_rejects_invalid_is_client() {
    let mut s = TunnelSession::default();
    s.is_client = 2;
    let mut packed = [0u8; SESSION_PACKED_BYTES];
    session_pack(&s, &mut packed).unwrap();
    let mut out = TunnelSession::default();
    assert_eq!(session_unpack(&packed, &mut out), Err(Error::Crypto));
}
