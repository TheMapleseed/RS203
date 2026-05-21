//! Wire bytes for `pack_line` must match MSGPACK-C `msgpack_pack_str` (see `_ref-203/MSGPACK-C`).

use fips203_core::pack_line;

#[test]
fn pack_fixstr_hello() {
    let mut buf = [0u8; 16];
    let n = pack_line(b"hello", &mut buf).unwrap();
    assert_eq!(n, 6);
    assert_eq!(&buf[..n], &[0xa5, b'h', b'e', b'l', b'l', b'o']);
}

#[test]
fn pack_fixstr_empty() {
    let mut buf = [0u8; 8];
    let n = pack_line(b"", &mut buf).unwrap();
    assert_eq!(n, 1);
    assert_eq!(&buf[..n], &[0xa0]);
}

#[test]
fn pack_fixstr_max_len() {
    let payload = vec![b'x'; 31];
    let mut buf = vec![0u8; 64];
    let n = pack_line(&payload, &mut buf).unwrap();
    assert_eq!(n, 32);
    assert_eq!(buf[0], 0xa0 | 31);
    assert_eq!(&buf[1..n], &payload[..]);
}

#[test]
fn pack_str8_min_len() {
    let payload = vec![b'y'; 32];
    let mut buf = vec![0u8; 64];
    let n = pack_line(&payload, &mut buf).unwrap();
    assert_eq!(n, 34);
    assert_eq!(&buf[..2], &[0xd9, 32]);
    assert_eq!(&buf[2..n], &payload[..]);
}
