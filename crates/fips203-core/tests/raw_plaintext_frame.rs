//! Record layer roundtrip for opaque plaintext (no MessagePack).

mod support;

use fips203_core::{read_wire_frame, write_wire_frame, MAX_MSG, MAX_WIRE};
use support::{client_to_server_plain, paired_sessions, server_to_client_plain};

use std::io::{Read, Write};

struct MemPipe {
    buf: Vec<u8>,
    pos: usize,
}

impl MemPipe {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
        }
    }
}

impl Write for MemPipe {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Read for MemPipe {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.buf.len() {
            return Ok(0);
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[test]
fn opaque_single_byte_and_chunk() {
    let (mut client, mut server) = paired_sessions();
    for plain in [
        &[0x00][..],
        &[0xFF, 0x7F, 0x00, 0x01][..],
        &(0u8..=255).collect::<Vec<_>>(),
    ] {
        let got = client_to_server_plain(&mut client, &mut server, plain);
        assert_eq!(got, plain);
    }
}

#[test]
fn opaque_max_plaintext_size() {
    let (mut client, mut server) = paired_sessions();
    let plain: Vec<u8> = (0..MAX_MSG).map(|i| (i & 0xff) as u8).collect();
    let got = client_to_server_plain(&mut client, &mut server, &plain);
    assert_eq!(got, plain);
}

#[test]
fn opaque_bidirectional_without_msgpack() {
    let (mut client, mut server) = paired_sessions();
    let c2s = [0xDE, 0xAD, 0xBE, 0xEF];
    let s2c = [1, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(
        client_to_server_plain(&mut client, &mut server, &c2s),
        c2s.as_slice()
    );
    assert_eq!(
        server_to_client_plain(&mut server, &mut client, &s2c),
        s2c.as_slice()
    );
}

#[test]
fn opaque_through_wire_framing() {
    use fips203_core::{frame_open, frame_seal};
    let (mut client, mut server) = paired_sessions();
    let plain: Vec<u8> = (0..512).map(|i| (i * 3 & 0xff) as u8).collect();
    let mut wire = [0u8; MAX_WIRE];
    let wl = frame_seal(&mut client, &plain, &mut wire).unwrap();

    let mut pipe = MemPipe::new();
    write_wire_frame(&mut pipe, &wire, wl).unwrap();
    pipe.pos = 0;
    let mut wire2 = [0u8; MAX_WIRE];
    let wl2 = read_wire_frame(&mut pipe, &mut wire2).unwrap();
    assert_eq!(wl2, wl);

    let mut out = [0u8; MAX_MSG];
    let ol = frame_open(&mut server, &wire2[..wl2], &mut out).unwrap();
    assert_eq!(&out[..ol], plain.as_slice());
}
