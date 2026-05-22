# fips203-tunnel

Tokio TCP tunnel and `fips203_tunnel` CLI — built on [`fips203-core`](https://crates.io/crates/fips203-core), wire-compatible with [TheMapleseed/203](https://github.com/TheMapleseed/203).

```toml
[dependencies]
fips203-tunnel = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

```rust
use fips203_tunnel::{from_env, TunnelLink};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cfg = from_env().expect("TUNNEL_* env");
    let mut link = TunnelLink::connect("127.0.0.1", 9999, &cfg).await?;
    link.send_line("hello").await?;
    link.shutdown();
    Ok(())
}
```

CLI (same env vars as the C `fips203_tunnel`):

```bash
export TUNNEL_PSK_HEX=<64 hex chars>
export TUNNEL_CLIENT_ID=alice
export TUNNEL_SERVER_ID=bob
fips203_tunnel server 9999
fips203_tunnel client 127.0.0.1 9999
```

Library docs: [`fips203_tunnel`](https://docs.rs/fips203_tunnel). Protocol/crypto: [`fips203_core`](https://docs.rs/fips203_core).
