//! TCP wire framing (length prefix + seq + epoch + ciphertext + tag).

use fips203_core::{MAX_MSG, MAX_WIRE, TAG};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn read_wire_frame(
    rd: &mut (impl AsyncRead + Unpin),
    wire: &mut [u8],
) -> std::io::Result<usize> {
    if wire.len() < MAX_WIRE {
        return Err(std::io::Error::other("wire buffer"));
    }
    let mut lb = [0u8; 4];
    let mut sb = [0u8; 8];
    let mut eb = [0u8; 4];
    rd.read_exact(&mut lb).await?;
    rd.read_exact(&mut sb).await?;
    rd.read_exact(&mut eb).await?;
    let n = u32::from_be_bytes(lb) as usize;
    if n > MAX_MSG {
        return Err(std::io::Error::other("frame too large"));
    }
    let total = 16 + n + TAG;
    if total > wire.len() {
        return Err(std::io::Error::other("wire overflow"));
    }
    wire[..4].copy_from_slice(&lb);
    wire[4..12].copy_from_slice(&sb);
    wire[12..16].copy_from_slice(&eb);
    if n > 0 {
        rd.read_exact(&mut wire[16..16 + n]).await?;
    }
    rd.read_exact(&mut wire[16 + n..total]).await?;
    Ok(total)
}

pub async fn write_wire_frame(
    wr: &mut (impl AsyncWrite + Unpin),
    wire: &[u8],
    wire_len: usize,
) -> std::io::Result<()> {
    wr.write_all(&wire[..wire_len]).await?;
    wr.flush().await?;
    Ok(())
}
