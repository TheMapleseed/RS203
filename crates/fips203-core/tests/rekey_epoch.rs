//! In-band rekey (REQ/ACK) then opaque + MessagePack payloads on the new epoch.

mod support;

use fips203_core::{
    build_control, is_control, pack_line, rekey_apply, CTRL_ACK, CTRL_LEN, CTRL_REQ,
    REKEY_NONCE_SIZE,
};
use support::{client_to_server_plain, paired_sessions, server_to_client_plain};

fn exchange_control(
    client: &mut fips203_core::TunnelSession,
    server: &mut fips203_core::TunnelSession,
    plain: &[u8; CTRL_LEN],
) -> [u8; CTRL_LEN] {
    let got = client_to_server_plain(client, server, plain);
    let mut out = [0u8; CTRL_LEN];
    out.copy_from_slice(&got[..CTRL_LEN]);
    out
}

#[test]
fn rekey_apply_only_keeps_c2s_aligned() {
    let (mut client, mut server) = paired_sessions();
    let cn = [0xC1u8; REKEY_NONCE_SIZE];
    let sn = [0x51u8; REKEY_NONCE_SIZE];
    rekey_apply(&mut client, 1, &cn, &sn);
    rekey_apply(&mut server, 1, &cn, &sn);
    assert_eq!(client.txe, server.rxe);
    assert_eq!(client.txm, server.rxm);
}

#[test]
fn rekey_epoch_bumps_then_opaque_and_msgpack_work() {
    let (mut client, mut server) = paired_sessions();
    assert_eq!(client.epoch, 0);
    assert_eq!(server.epoch, 0);
    assert_eq!(client.txe, server.rxe, "paired c2s before rekey");

    let client_nonce = [0xC1u8; REKEY_NONCE_SIZE];
    let server_nonce = [0x51u8; REKEY_NONCE_SIZE];
    let new_epoch = 1u32;

    let mut req = [0u8; CTRL_LEN];
    build_control(&mut req, CTRL_REQ, new_epoch, &client_nonce);
    let opened = exchange_control(&mut client, &mut server, &req);

    let mut ty = 0u8;
    let mut epoch = 0u32;
    let mut peer_nonce = [0u8; REKEY_NONCE_SIZE];
    assert!(is_control(&opened, &mut ty, &mut epoch, &mut peer_nonce));
    assert_eq!(ty, CTRL_REQ);
    assert_eq!(epoch, new_epoch);
    assert_eq!(peer_nonce, client_nonce);

    // C sends ACK on pre-rekey keys, then both sides apply `rekey_apply`.
    let mut ack = [0u8; CTRL_LEN];
    build_control(&mut ack, CTRL_ACK, new_epoch, &server_nonce);
    let ack_opened = server_to_client_plain(&mut server, &mut client, &ack);
    assert!(is_control(&ack_opened, &mut ty, &mut epoch, &mut peer_nonce));
    assert_eq!(ty, CTRL_ACK);

    rekey_apply(&mut server, new_epoch, &client_nonce, &server_nonce);
    rekey_apply(&mut client, new_epoch, &client_nonce, &server_nonce);

    assert_eq!(client.epoch, new_epoch);
    assert_eq!(server.epoch, new_epoch);
    assert_eq!(client.txe, server.rxe, "c2s enc key");
    assert_eq!(client.txm, server.rxm, "c2s mac key");
    assert_eq!(client.txb, server.rxb, "c2s nonce base");

    let opaque = [0xAA, 0xBB, 0xCC, 0xDD];
    assert_eq!(
        client_to_server_plain(&mut client, &mut server, &opaque),
        opaque.as_slice()
    );

    let mut mp = [0u8; 64];
    let plen = pack_line(b"after-rekey", &mut mp).unwrap();
    assert_eq!(
        client_to_server_plain(&mut client, &mut server, &mp[..plen]),
        &mp[..plen]
    );
}
