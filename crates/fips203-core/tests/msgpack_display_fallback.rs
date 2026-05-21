//! Tunnel recv path: string → raw decode; non-string → format_decoded (C bypass).

use fips203_core::{decode_string_only, format_decoded, pack_line};

#[test]
fn string_uses_raw_path_not_quoted() {
    let mut wire = vec![0u8; 128];
    let wlen = pack_line(b"say \"hi\"", &mut wire).unwrap();
    let mut raw = vec![0u8; 4096];
    assert!(decode_string_only(&wire[..wlen], &mut raw).is_ok());
    let rlen = decode_string_only(&wire[..wlen], &mut raw).unwrap();
    assert_eq!(&raw[..rlen], b"say \"hi\"");

    let mut fmt = vec![0u8; 4096];
    let flen = format_decoded(&wire[..wlen], &mut fmt).unwrap();
    let formatted = std::str::from_utf8(&fmt[..flen]).unwrap();
    assert!(formatted.contains('\\'));
    assert!(formatted.starts_with('"'));
}

#[test]
fn quit_payload() {
    use fips203_core::payload_is_quit;
    let mut wire = vec![0u8; 32];
    let wlen = pack_line(b"quit", &mut wire).unwrap();
    assert!(payload_is_quit(&wire[..wlen]));
    let wlen2 = pack_line(b"quitter", &mut wire).unwrap();
    assert!(!payload_is_quit(&wire[..wlen2]));
}
