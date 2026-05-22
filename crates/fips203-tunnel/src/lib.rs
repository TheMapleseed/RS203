//! # fips203-tunnel
//!
//! Tokio TCP tunnel: PSK + ML-KEM-768 handshake, FIPS203TUNNEL-GCM records, in-band rekey.
//!
//! Wire-compatible with [TheMapleseed/203](https://github.com/TheMapleseed/203) `fips203_tunnel`.
//! Crypto and framing live in [`fips203_core`]; this crate runs the live session over async TCP.
//!
//! ## Quick start
//!
//! ```no_run
//! use fips203_tunnel::{from_env, TunnelLink};
//!
//! # #[tokio::main]
//! # async fn main() -> std::io::Result<()> {
//! let cfg = from_env().map_err(|e| std::io::Error::other(e))?;
//! let mut link = TunnelLink::connect("127.0.0.1", 9999, &cfg).await?;
//! link.send_line("hello").await?;
//! link.shutdown();
//! # Ok(())
//! # }
//! ```

pub mod client;
pub mod config;
pub mod crypto_tunnel;
#[macro_use]
mod debug;
pub mod link;
pub mod runtime;
pub mod server;
mod shutdown;
mod wire;

pub use client::run_client;
pub use config::{
    from_env, parse_port, load_tunnel_env, TunnelConfig, TunnelEnv, DEFAULT_REKEY_INTERVAL,
    ID_SIZE, QUEUE_DEPTH_DEFAULT, REKEY_NONCE_SIZE,
};
pub use crypto_tunnel::{
    build_control, handshake_client, handshake_server, is_control, rekey_apply, seal_frame,
    open_frame, SessionHandle, CTRL_ACK, CTRL_LEN, CTRL_MAGIC, CTRL_REQ,
};
pub use link::{LinkMode, TunnelLink};
pub use runtime::{display_plain, recv_loop, send_plain, tx_loop, PlainMsg, SharedSession, WriteHalf};
pub use server::run_server;
