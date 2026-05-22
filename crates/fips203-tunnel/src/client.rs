//! Client mode: stdin → MsgPack → encrypt; decrypt → display.

use fips203_core::MAX_MSG;

use crate::config::TunnelConfig;
use crate::link::{LinkMode, TunnelLink};

pub async fn run_client(host: &str, port: u16, cfg: TunnelConfig) -> std::io::Result<()> {
    if cfg.queue_clamped() {
        eprintln!(
            "client: queue depth clamped to {} (~{} KiB per plaintext queue)",
            cfg.queue_depth(),
            (cfg.queue_depth() * (std::mem::size_of::<u32>() + MAX_MSG) + 1023) / 1024
        );
    }
    println!(
        "client: connecting to {host}:{port} (queues depth={}, ~{} KiB per plaintext queue)",
        cfg.queue_depth(),
        (cfg.queue_depth() * (std::mem::size_of::<u32>() + MAX_MSG) + 1023) / 1024
    );
    eprintln!("client: plaintext = ASCII lines → MessagePack string → encrypt (stdin)");

    let link = TunnelLink::connect_mode(host, port, &cfg, LinkMode::StdinClient).await?;
    println!("client: handshake complete");
    link.run_until_close().await
}
