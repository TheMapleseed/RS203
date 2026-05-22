//! Decoder accepts MSGPACK-C-shaped string wire bytes (not only our own packer).

use fips203_core::{decode_string_only, pack_line};

#[test]
fn decode_fixstr_wire_from_constants() {
    let wire = [0xa5, b'h', b'e', b'l', b'l', b'o'];
    let mut out = [0u8; 16];
    let n = decode_string_only(&wire, &mut out).unwrap();
    assert_eq!(&out[..n], b"hello");
}

#[test]
fn decode_str8_wire_from_constants() {
    let payload = vec![b'z'; 32];
    let mut wire = vec![0xd9, 32];
    wire.extend_from_slice(&payload);
    let mut out = vec![0u8; 64];
    let n = decode_string_only(&wire, &mut out).unwrap();
    assert_eq!(&out[..n], &payload);
}

#[test]
fn pack_then_decode_matches_constants() {
    let mut packed = [0u8; 16];
    let n = pack_line(b"hello", &mut packed).unwrap();
    assert_eq!(&packed[..n], &[0xa5, b'h', b'e', b'l', b'l', b'o']);
    let mut out = [0u8; 16];
    let m = decode_string_only(&packed[..n], &mut out).unwrap();
    assert_eq!(&out[..m], b"hello");
}
