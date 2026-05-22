# RS203 — Rust library for [TheMapleseed/203](https://github.com/TheMapleseed/203)

[![crates.io](https://img.shields.io/crates/v/fips203-core.svg)](https://crates.io/crates/fips203-core)
[![docs.rs](https://docs.rs/fips203-core/badge.svg)](https://docs.rs/fips203-core)
[![license](https://img.shields.io/crates/l/fips203-core.svg)](https://github.com/TheMapleseed/RS203/blob/main/LICENSE)

Post-quantum–ready encrypted tunnel: **ML-KEM-768** (FIPS 203), **FIPS203TUNNEL-GCM** records, PSK+KEM handshake, in-band rekey, and MsgPack string lines. Pure Rust, wire-compatible with the C `fips203_tunnel` — not FFI wrappers around the C tree.

## crates.io

```toml
[dependencies]
fips203-core = "0.1"
# async TCP tunnel + CLI binary:
fips203-tunnel = "0.1"
```

See [PUBLISHING.md](PUBLISHING.md) for release steps.

## Crates

| Crate | Role |
| --- | --- |
| [`fips203-core`](crates/fips203-core) | **Library** — crypto, frames, handshake, rekey, MsgPack (`std` only, **zero non-std deps**) |
| [`fips203-tunnel`](crates/fips203-tunnel) | **Library + CLI** — Tokio TCP tunnel (`fips203_tunnel` binary), [`TunnelLink`](crates/fips203-tunnel/src/link.rs) for async apps |

### `fips203-core` — embed anywhere

```toml
[dependencies]
fips203-core = "0.1"
```

```rust
use std::net::TcpStream;
use fips203_core::{
    handshake_client, load_handshake_config_from_env, load_rekey_interval_from_env,
    TunnelRuntime,
};
```

Blocking `std::net` sample: `cargo run -p fips203-core --example loopback_std -- …`

### `fips203-tunnel` — async TCP session

```toml
[dependencies]
fips203-tunnel = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

```rust
use fips203_tunnel::{from_env, LinkMode, TunnelLink};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cfg = from_env().expect("TUNNEL_* env");
    let mut link = TunnelLink::connect("127.0.0.1", 9999, &cfg).await?;
    link.send_line("hello").await?;
    if let Some(payload) = link.recv_payload().await? {
        println!("got {} bytes", payload.len());
    }
    link.shutdown();
    link.join().await;
    Ok(())
}
```

CLI modes (`StdinClient` / `EchoServer`) are built on the same [`TunnelLink`](crates/fips203-tunnel/src/link.rs); use `LinkMode::Application` when you drive I/O yourself.

## Tests

```bash
cargo test --workspace
cargo build -p fips203-tunnel --release
```

| Area | Tests |
| --- | --- |
| **MsgPack** | `msgpack_*`, `msgpack_vs_opaque_frame` |
| **Opaque plaintext** | `raw_plaintext_frame`, `frame_smoke`, `wire_roundtrip` |
| **Handshake / rekey** | `handshake_duplex`, `rekey_epoch`, `handshake_tcp` |
| **Live TCP** | `tunnel_link_loopback` (opaque + MsgPack via `TunnelLink`) |
| **C interop** | `scripts/interop_tunnel.sh`, `interop_rekey.sh` |

## CLI

```bash
cargo build -p fips203-tunnel --release
export TUNNEL_PSK_HEX=<64 hex chars>
export TUNNEL_CLIENT_ID=alice
export TUNNEL_SERVER_ID=bob
./target/release/fips203_tunnel server 9999
./target/release/fips203_tunnel client 127.0.0.1 9999
```

Optional: `TUNNEL_QUEUE_DEPTH`, `TUNNEL_MAX_QUEUE_MB`, `TUNNEL_MAX_QUEUE_BYTES`, `TUNNEL_REKEY_INTERVAL`.

## Wire interop (optional, vs C `fips203_tunnel`)

```bash
git clone --depth 1 https://github.com/TheMapleseed/203.git _ref-203
./scripts/interop_tunnel.sh
./scripts/interop_rekey.sh
./scripts/rust_tunnel_smoke.sh
```

## C reference map

| C | Rust |
| --- | --- |
| `fips203_frame.c` | `fips203-core` — `frame.rs`, `session.rs` |
| `fips203_msgpack.c` | `fips203-core` — `msgpack.rs` |
| `mlkem.c` + PQClean | `fips203-core` — `mlkem/pqclean768/` |
| `tunnel_main.c` (protocol) | `fips203-core` — `tunnel.rs` |
| `tunnel_main.c` (TCP) | `fips203-tunnel` — `link.rs`, `runtime.rs`, `fips203_tunnel` binary |

## License

**MIT OR Apache-2.0** (`LICENSE`). Building the upstream C tunnel for interop uses **GPLv3** (203).
