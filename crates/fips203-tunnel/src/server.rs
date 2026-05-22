//! Server mode: decrypt → display → echo plaintext back on same TCP stream.

use fips203_core::MAX_MSG;

use crate::config::TunnelConfig;
use crate::link::{LinkMode, TunnelLink};

pub async fn run_server(port: u16, cfg: TunnelConfig) -> std::io::Result<()> {
    println!("server: listening on port {port}");
    if cfg.queue_clamped() {
        eprintln!(
            "server: queue depth clamped to {} (~{} bytes for plaintext queue)",
            cfg.queue_depth(),
            cfg.queue_depth() * (std::mem::size_of::<u32>() + MAX_MSG)
        );
    }

    let (link, addr) = TunnelLink::accept_mode(port, &cfg, LinkMode::EchoServer).await?;
    println!(
        "server: peer {addr} — handshake complete (queue depth={}, ~{} KiB plaintext buffer)",
        cfg.queue_depth(),
        (cfg.queue_depth() * (std::mem::size_of::<u32>() + MAX_MSG) + 1023) / 1024
    );
    eprintln!("server: decrypt → MessagePack decode → display (ASCII source lines on client)");
    link.run_until_close().await
}
