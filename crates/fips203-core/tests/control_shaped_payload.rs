//! A 41-byte `RKY1`-shaped payload must round-trip as application data, not be dropped.

mod support;

use fips203_core::CTRL_LEN;
use support::{client_to_server_plain, paired_sessions};

#[test]
fn rky1_shaped_opaque_payload_is_not_dropped() {
    let (mut client, mut server) = paired_sessions();
    let mut payload = [0u8; CTRL_LEN];
    payload[..4].copy_from_slice(b"RKY1");
    payload[4] = 0xFF; // not CTRL_REQ / CTRL_ACK
    payload[5..9].copy_from_slice(&[0, 0, 0, 1]);
    payload[9..].fill(0xAB);

    let got = client_to_server_plain(&mut client, &mut server, &payload);
    assert_eq!(got, payload.as_slice());
}
