//! Session blob layout matches `fips203_session_pack` / `unpack` in `fips203_frame.c`.

use fips203_core::{
    session_pack, session_unpack, TunnelSession, SESSION_ID_SIZE, SESSION_PACKED_BYTES,
};

#[test]
fn session_pack_unpack_roundtrip() {
    let mut s = TunnelSession::default();
    s.txe = [0x01; 32];
    s.txm = [0x02; 32];
    s.rxe = [0x03; 32];
    s.rxm = [0x04; 32];
    s.txb = [0x05; 12];
    s.rxb = [0x06; 12];
    s.txs = 7;
    s.rxs = 8;
    s.session_id = [0x09; SESSION_ID_SIZE];
    s.epoch = 2;
    s.is_client = 1;
    s.rekey_interval = 100_000;

    let mut packed = [0u8; SESSION_PACKED_BYTES];
    session_pack(&s, &mut packed).unwrap();
    let mut out = TunnelSession::default();
    session_unpack(&packed, &mut out).unwrap();

    assert_eq!(out.txe, s.txe);
    assert_eq!(out.txm, s.txm);
    assert_eq!(out.rxe, s.rxe);
    assert_eq!(out.rxm, s.rxm);
    assert_eq!(out.txb, s.txb);
    assert_eq!(out.rxb, s.rxb);
    assert_eq!(out.txs, s.txs);
    assert_eq!(out.rxs, s.rxs);
    assert_eq!(out.session_id, s.session_id);
    assert_eq!(out.epoch, s.epoch);
    assert_eq!(out.is_client, s.is_client);
    assert_eq!(out.rekey_interval, s.rekey_interval);
}
