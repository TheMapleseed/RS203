# fips203-core

Pure-Rust **ML-KEM-768** and **FIPS203TUNNEL-GCM** tunnel protocol — wire-compatible with [TheMapleseed/203](https://github.com/TheMapleseed/203).

- PSK + ML-KEM handshake, in-band rekey, length-prefixed wire frames
- MessagePack helpers for 7-bit ASCII lines (optional; opaque plaintext is also supported)
- `std` only, **no non-std Cargo dependencies**

```toml
[dependencies]
fips203-core = "0.1"
```

```rust
use fips203_core::{TunnelRuntime, handshake_client, seal_plain, open_plain, load_handshake_config_from_env};
```

See the [repository README](https://github.com/TheMapleseed/RS203) for env vars, examples, and C interop.
