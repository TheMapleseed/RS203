//! Same session carries MessagePack string lines and opaque bytes; only the former decodes as ASCII.

mod support;

use fips203_core::{decode_string_only, pack_line, MAX_MSG};
use support::{client_to_server_plain, paired_sessions};

#[test]
fn msgpack_line_and_opaque_both_roundtrip() {
    let (mut client, mut server) = paired_sessions();

    let mut mp = [0u8; 64];
    let plen = pack_line(b"hello", &mut mp).unwrap();
    let got_mp = client_to_server_plain(&mut client, &mut server, &mp[..plen]);
    assert_eq!(&got_mp, &mp[..plen]);

    let opaque = [0x00, 0xFF, 0xA5, b'h']; // not a valid lone fixstr line
    let got_raw = client_to_server_plain(&mut client, &mut server, &opaque);
    assert_eq!(got_raw, opaque);

    let mut ascii = [0u8; MAX_MSG];
    let n = decode_string_only(&got_mp, &mut ascii).expect("msgpack decodes");
    assert_eq!(&ascii[..n], b"hello");
    assert!(decode_string_only(&got_raw, &mut ascii).is_err());
}

#[test]
fn opaque_is_not_treated_as_quit() {
    use fips203_core::{pack_line, payload_is_quit};
    let (mut client, mut server) = paired_sessions();

    let mut quit_mp = [0u8; 16];
    let qlen = pack_line(b"quit", &mut quit_mp).unwrap();
    assert!(payload_is_quit(&quit_mp[..qlen]));

    let fake = [0xA4, b'q', b'u', b'i', b'X']; // fixstr "quiX" — wrong quit
    assert!(!payload_is_quit(&fake));
    let got = client_to_server_plain(&mut client, &mut server, &fake);
    assert_eq!(got, fake);
}
