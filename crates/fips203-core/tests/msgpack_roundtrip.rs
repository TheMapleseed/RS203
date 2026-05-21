//! Mirrors `tests/fips203_msgpack_roundtrip.c` (MSGPACK-C + fips203_msgpack.c).

use fips203_core::{ascii_valid, decode_string_only, pack_line};

fn roundtrip(line: &str) {
    let ascii = line.as_bytes();
    assert!(ascii_valid(ascii));
    let mut packed = vec![0u8; 4096 + 64];
    let plen = pack_line(ascii, &mut packed).expect("pack_line");
    let mut out = vec![0u8; 4096 + 64];
    let olen = decode_string_only(&packed[..plen], &mut out).expect("decode_string_only");
    assert_eq!(&out[..olen], ascii);
}

#[test]
fn msgpack_ascii_roundtrip() {
    roundtrip("hello");
    roundtrip("a\"b\\c");
    roundtrip("");
    roundtrip("say \"hi\"");
}
