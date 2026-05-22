//! TCP length-prefixed wire framing (header + ciphertext + tag), `tunnel_main.c` `read_wire_frame`.

use std::io::{self, Read, Write};

use crate::frame::{MAX_MSG, MAX_WIRE, TAG};

/// Read one complete frame into `wire` (capacity ≥ [`MAX_WIRE`]). Returns total bytes stored.
pub fn read_wire_frame(rd: &mut impl Read, wire: &mut [u8]) -> io::Result<usize> {
    if wire.len() < MAX_WIRE {
        return Err(io::Error::other("wire buffer"));
    }
    let mut lb = [0u8; 4];
    let mut sb = [0u8; 8];
    let mut eb = [0u8; 4];
    rd.read_exact(&mut lb)?;
    rd.read_exact(&mut sb)?;
    rd.read_exact(&mut eb)?;
    let n = u32::from_be_bytes(lb) as usize;
    if n > MAX_MSG {
        return Err(io::Error::other("frame too large"));
    }
    let total = 16 + n + TAG;
    if total > wire.len() {
        return Err(io::Error::other("wire overflow"));
    }
    wire[..4].copy_from_slice(&lb);
    wire[4..12].copy_from_slice(&sb);
    wire[12..16].copy_from_slice(&eb);
    if n > 0 {
        rd.read_exact(&mut wire[16..16 + n])?;
    }
    rd.read_exact(&mut wire[16 + n..total])?;
    Ok(total)
}

/// Write a sealed frame buffer to the stream.
pub fn write_wire_frame(wr: &mut impl Write, wire: &[u8], wire_len: usize) -> io::Result<()> {
    wr.write_all(&wire[..wire_len])?;
    wr.flush()?;
    Ok(())
}
