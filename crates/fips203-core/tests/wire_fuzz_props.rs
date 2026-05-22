//! Property tests: malformed wire/session input must not panic and must fail safely.

use fips203_core::{
    frame_open, frame_seal, session_unpack, TunnelSession, MAX_MSG, MAX_WIRE, SESSION_PACKED_BYTES,
};
use proptest::prelude::*;

proptest! {
    #[test]
    fn frame_open_never_panics_on_arbitrary_wire(wire in prop::collection::vec(any::<u8>(), 0..=MAX_WIRE + 64)) {
        let mut session = seeded_session();
        let mut plain = [0u8; MAX_MSG];
        let _ = frame_open(&mut session, &wire, &mut plain);
    }

    #[test]
    fn frame_seal_rejects_oversized_plain(plain in prop::collection::vec(any::<u8>(), MAX_MSG + 1..=MAX_MSG + 64)) {
        let mut session = seeded_session();
        let mut wire = [0u8; MAX_WIRE];
        prop_assert!(frame_seal(&mut session, &plain, &mut wire).is_err());
    }

    #[test]
    fn session_unpack_never_panics(blob in prop::collection::vec(any::<u8>(), 0..=SESSION_PACKED_BYTES + 32)) {
        let mut session = TunnelSession::default();
        let _ = session_unpack(&blob, &mut session);
    }
}

fn seeded_session() -> TunnelSession {
    let mut session = TunnelSession::default();
    session.txe = [1u8; 32];
    session.txm = [2u8; 32];
    session.rxe = [3u8; 32];
    session.rxm = [4u8; 32];
    session.txb = [5u8; 12];
    session.rxb = [6u8; 12];
    session.session_id = [7u8; 16];
    session
}
