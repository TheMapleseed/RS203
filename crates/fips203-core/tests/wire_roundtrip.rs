//! Wire framing roundtrip over an in-memory pipe.

use std::io::{Read, Write};

use fips203_core::{
    frame_open, frame_seal, read_wire_frame, write_wire_frame, TunnelSession, MAX_MSG, MAX_WIRE,
};

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
fn seal_write_read_open_roundtrip() {
    let mut s = TunnelSession::default();
    s.txe = [0x42; 32];
    s.txm = [0x43; 32];
    s.rxe = s.txe;
    s.rxm = s.txm;
    s.txb = [0x44; 12];
    s.rxb = s.txb;

    let plain = [1u8, 2, 3, 4, 5];
    let mut wire = [0u8; MAX_WIRE];
    let wl = frame_seal(&mut s, &plain, &mut wire).unwrap();

    let mut pipe = MemPipe::new();
    write_wire_frame(&mut pipe, &wire, wl).unwrap();
    pipe.pos = 0;

    let mut wire2 = [0u8; MAX_WIRE];
    let wl2 = read_wire_frame(&mut pipe, &mut wire2).unwrap();
    assert_eq!(wl2, wl);

    let mut out = [0u8; MAX_MSG];
    let ol = frame_open(&mut s, &wire2[..wl2], &mut out).unwrap();
    assert_eq!(&out[..ol], &plain);
}
