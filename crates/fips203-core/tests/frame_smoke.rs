//! Mirrors `test/tframe_smoke.c`.

use fips203_core::{frame_open, frame_seal, TunnelSession, MAX_MSG, MAX_WIRE};

#[test]
fn frame_roundtrip_matches_c_smoke() {
    let mut s = TunnelSession::default();
    s.txe = [0x42; 32];
    s.txm = [0x43; 32];
    s.rxe = s.txe;
    s.rxm = s.txm;
    s.txb = [0x44; 12];
    s.rxb = s.txb;

    let plain = [1u8, 2, 3, 4, 5];
    let mut wire = [0u8; MAX_WIRE];
    let wl = frame_seal(&mut s, &plain, &mut wire).expect("seal");
    let mut out = [0u8; MAX_MSG];
    let ol = frame_open(&mut s, &wire[..wl], &mut out).expect("open");
    assert_eq!(ol, plain.len());
    assert_eq!(&out[..ol], &plain);
}
