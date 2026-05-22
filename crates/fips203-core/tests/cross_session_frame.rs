//! Server seal → client open with opposed derive_tunnel_session roles (post-handshake shape).

use fips203_core::{
    derive_tunnel_session, frame_open, frame_seal, pack_line, TunnelSession, SESSION_ID_SIZE,
};

#[test]
fn server_sealed_hello_opens_on_client() {
    let ss = [0x11u8; 32];
    let ns = [0x22u8; 32];
    let nc = [0x33u8; 32];
    let sid = [0x44u8; SESSION_ID_SIZE];
    let mut server = TunnelSession::default();
    let mut client = TunnelSession::default();
    derive_tunnel_session(&mut server, &ss, &ns, &nc, &sid, false);
    derive_tunnel_session(&mut client, &ss, &ns, &nc, &sid, true);

    let mut mp = [0u8; 64];
    let plen = pack_line(b"hello", &mut mp).unwrap();
    let mut wire = [0u8; 4096];
    let wl = frame_seal(&mut server, &mp[..plen], &mut wire).unwrap();

    let mut plain = [0u8; 4096];
    let ol = frame_open(&mut client, &wire[..wl], &mut plain).unwrap();
    assert_eq!(&plain[..ol], &mp[..plen]);
}
