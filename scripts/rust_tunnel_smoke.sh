#!/usr/bin/env bash
# Loopback Rust-only smoke (no C reference required).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${TUNNEL_SMOKE_PORT:-19002}"
export TUNNEL_PSK_HEX="${TUNNEL_PSK_HEX:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
export TUNNEL_CLIENT_ID="${TUNNEL_CLIENT_ID:-smoke_client}"
export TUNNEL_SERVER_ID="${TUNNEL_SERVER_ID:-smoke_server}"
export TUNNEL_REKEY_INTERVAL="${TUNNEL_REKEY_INTERVAL:-1000000000}"

if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
  BIN="${CARGO_TARGET_DIR}/release/fips203_tunnel"
else
  BIN="${ROOT}/target/release/fips203_tunnel"
fi

[[ -x "${BIN}" ]] || (cd "${ROOT}" && cargo build -p fips203-tunnel --release)

"${BIN}" server "${PORT}" > /tmp/rs203_smoke_srv.log 2>&1 &
SP=$!
sleep 0.4
( echo hello; sleep 0.2; echo quit ) | "${BIN}" client 127.0.0.1 "${PORT}" > /tmp/rs203_smoke_cli.log 2>&1
wait "${SP}" 2>/dev/null || true

grep -q 'server rx: hello' /tmp/rs203_smoke_srv.log
grep -q 'client rx: hello' /tmp/rs203_smoke_cli.log
echo "rust_tunnel_smoke: OK"
