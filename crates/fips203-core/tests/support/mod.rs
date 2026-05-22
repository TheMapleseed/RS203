//! Shared fixtures for integration tests.

use fips203_core::{
    frame_open, frame_seal, derive_tunnel_session, HandshakeConfig, TunnelSession, PEER_ID_SIZE,
    SESSION_ID_SIZE,
};

pub fn peer_id(label: &[u8]) -> [u8; PEER_ID_SIZE] {
    assert!(label.len() <= PEER_ID_SIZE);
    let mut out = [0u8; PEER_ID_SIZE];
    out[..label.len()].copy_from_slice(label);
    out
}

pub fn test_handshake_config() -> HandshakeConfig {
    HandshakeConfig {
        psk: [0xAB; 32],
        client_id: peer_id(b"test_client"),
        server_id: peer_id(b"test_server"),
    }
}

/// Post-handshake client/server sessions with opposed roles (no TCP).
pub fn paired_sessions() -> (TunnelSession, TunnelSession) {
    let ss = [0x51u8; 32];
    let ns = [0x52u8; 32];
    let nc = [0x53u8; 32];
    let sid = [0x54u8; SESSION_ID_SIZE];
    let mut client = TunnelSession::default();
    let mut server = TunnelSession::default();
    derive_tunnel_session(&mut client, &ss, &ns, &nc, &sid, true);
    derive_tunnel_session(&mut server, &ss, &ns, &nc, &sid, false);
    debug_assert_eq!(client.is_client, 1);
    debug_assert_eq!(server.is_client, 0);
    (client, server)
}

/// Client `frame_seal` → server `frame_open`.
pub fn client_to_server_plain(
    client: &mut TunnelSession,
    server: &mut TunnelSession,
    plain: &[u8],
) -> Vec<u8> {
    let mut wire = [0u8; fips203_core::MAX_WIRE];
    let wl = frame_seal(client, plain, &mut wire).expect("seal");
    let mut out = [0u8; fips203_core::MAX_MSG];
    let ol = frame_open(server, &wire[..wl], &mut out).expect("open");
    out[..ol].to_vec()
}

/// Server `frame_seal` → client `frame_open`.
pub fn server_to_client_plain(
    server: &mut TunnelSession,
    client: &mut TunnelSession,
    plain: &[u8],
) -> Vec<u8> {
    let mut wire = [0u8; fips203_core::MAX_WIRE];
    let wl = frame_seal(server, plain, &mut wire).expect("seal");
    let mut out = [0u8; fips203_core::MAX_MSG];
    let ol = frame_open(client, &wire[..wl], &mut out).expect("open");
    out[..ol].to_vec()
}
