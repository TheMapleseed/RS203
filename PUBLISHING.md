# Publishing to crates.io

Publish **`fips203-core` first**, then **`fips203-tunnel`** (the tunnel crate depends on the published version).

## Prerequisites

- [crates.io](https://crates.io) account and `cargo login`
- Clean git tree (or pass `--allow-dirty` while iterating)
- `cargo test --workspace` and interop scripts green

## Dry run

```bash
cargo package -p fips203-core --allow-dirty
# Tunnel verify needs `fips203-core` on crates.io OR skip verify until after the first core publish:
cargo package -p fips203-tunnel --allow-dirty --no-verify
```

`cargo package -p fips203-core` succeeds standalone. `fips203-tunnel` packaging resolves `fips203-core` from crates.io (path is stripped from the upload manifest), so **`fips203-core` must be published first**; use `--no-verify` only if you are checking the tarball layout before the index has the dependency.

Inspect the `.crate` tarballs under `target/package/` if needed.

## Publish

```bash
cargo publish -p fips203-core
# wait for index; then:
cargo publish -p fips203-tunnel
```

## After release

- Tag the repo: `git tag v0.1.0 && git push origin v0.1.0`
- docs.rs builds automatically from the tagged crates
- Bump `version` in `[workspace.package]` and `[workspace.dependencies]` for the next release

## Crate names on crates.io

| Package | Library / binary |
| --- | --- |
| `fips203-core` | `fips203_core` |
| `fips203-tunnel` | `fips203_tunnel` (+ `fips203_tunnel` binary) |

If a name is already taken, choose a new package name and update `workspace.dependencies` accordingly.
