#!/usr/bin/env bash
# Rekey wire-compat: force epoch bump after a few client frames (TUNNEL_REKEY_INTERVAL=2).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${TUNNEL_INTEROP_PORT:-19004}"
export TUNNEL_PSK_HEX="${TUNNEL_PSK_HEX:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
export TUNNEL_CLIENT_ID="${TUNNEL_CLIENT_ID:-interop_client}"
export TUNNEL_SERVER_ID="${TUNNEL_SERVER_ID:-interop_server}"
export TUNNEL_REKEY_INTERVAL=2

C_BIN="${ROOT}/_ref-203/fips203_tunnel"
RUST_BIN=""

rust_target_dir() {
  if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
    printf '%s' "${CARGO_TARGET_DIR}"
  else
    printf '%s/target' "${ROOT}"
  fi
}

RUST_BIN="$(rust_target_dir)/release/fips203_tunnel"

log() { printf '[rekey-interop] %s\n' "$*"; }
die() { printf '[rekey-interop] ERROR: %s\n' "$*" >&2; exit 1; }

[[ -x "${C_BIN}" ]] || make -C "${ROOT}/_ref-203" fips203_tunnel
[[ -x "${RUST_BIN}" ]] || (cd "${ROOT}" && cargo build -p fips203-tunnel --release)

run_case() (
  local name="$1"
  local server_cmd="$2"
  local client_cmd="$3"
  local srv_log cli_log srv_pid
  srv_log="$(mktemp)"
  cli_log="$(mktemp)"
  trap 'rm -f "${srv_log}" "${cli_log}"; kill ${srv_pid:-} 2>/dev/null || true' EXIT

  bash -c "${server_cmd}" >"${srv_log}" 2>&1 &
  srv_pid=$!
  sleep 0.5

  # Four lines → client txs crosses rekey_interval=2 on line 3.
  if ! bash -c "( echo a; echo b; sleep 0.2; echo c; sleep 0.2; echo quit ) | ${client_cmd}" >"${cli_log}" 2>&1; then
    cat "${srv_log}" >&2
    cat "${cli_log}" >&2
    die "${name}: client failed"
  fi

  kill "${srv_pid}" 2>/dev/null || true
  wait "${srv_pid}" 2>/dev/null || true

  grep -q 'client: handshake complete' "${cli_log}" || die "${name}: no handshake"
  grep -q 'client rx: a' "${cli_log}" || die "${name}: missing echo a"
  log "CASE ${name}: OK"
)

run_case "rust_client_c_server" \
  "${C_BIN} server ${PORT}" \
  "${RUST_BIN} client 127.0.0.1 ${PORT}"

run_case "c_client_rust_server" \
  "${RUST_BIN} server ${PORT}" \
  "${C_BIN} client 127.0.0.1 ${PORT}"

log "Rekey interop cases passed."
