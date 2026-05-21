# RS203 — Rust port of [TheMapleseed/203](https://github.com/TheMapleseed/203)

Post-quantum–ready encrypted tunnel built around **ML-KEM-768** (FIPS 203) and the **FIPS203TUNNEL-GCM** record layer (SHAKE256 + SHA3-256, GCM-like framing). This repository is a **Rust reimplementation** intended to stay **wire-compatible** with the C reference.

## What exists today

| Crate / binary | Status |
| --- | --- |
| [`fips203-core`](crates/fips203-core) | **Pure Rust** (`std` only): PQClean ML-KEM-768 clean, FIPS202, frames, MsgPack helpers |
| [`fips203_tunnel`](crates/fips203-tunnel) | **`fips203_tunnel`** binary (tokio): PSK+ML-KEM handshake, bounded queues, in-band rekey, MsgPack stdin client |

### Tests (parity with C smoke tests)

```bash
cargo test -p fips203-core
```

- `frame_smoke` — same vectors as `test/tframe_smoke.c`
- `msgpack_roundtrip` — same cases as `tests/fips203_msgpack_roundtrip.c`

## Run the tunnel

```bash
cargo build -p fips203-tunnel --release
export TUNNEL_PSK_HEX=<64 hex chars>
export TUNNEL_CLIENT_ID=alice
export TUNNEL_SERVER_ID=bob
./target/release/fips203_tunnel server 9999   # terminal 1
./target/release/fips203_tunnel client 127.0.0.1 9999   # terminal 2 — type ASCII lines
```

## Roadmap

1. **Interop tests** — Rust client ↔ C server and vice versa on a loopback port.
2. **FFI / bindings** — optional `cdylib` for Python/Node.

## Environment

Same as the C project:

```bash
export TUNNEL_PSK_HEX=<64 hex chars>
export TUNNEL_CLIENT_ID=<label>
export TUNNEL_SERVER_ID=<label>
```

Optional queue/rekey knobs: `TUNNEL_MAX_QUEUE_MB`, `TUNNEL_MAX_QUEUE_BYTES`, `TUNNEL_QUEUE_DEPTH`, `TUNNEL_REKEY_INTERVAL`.

## Reference layout (C repo)

| C path | Rust equivalent |
| --- | --- |
| `src/fips203_frame.c` | `crates/fips203-core/src/frame.rs` |
| `src/fips203_msgpack.c` + MSGPACK-C | `crates/fips203-core/src/msgpack.rs` |
| `src/mlkem.c` + PQClean | `crates/fips203-core/src/mlkem/pqclean768/` |
| `src/tunnel_main.c` | `crates/fips203-tunnel` (planned) |

A shallow clone of the C tree for local diffing may live in `_ref-203/` (gitignored).

## License

Match the upstream [203](https://github.com/TheMapleseed/203) license when you publish; this scaffold does not include `LICENSE` yet — add the same terms as the parent repo before release.
