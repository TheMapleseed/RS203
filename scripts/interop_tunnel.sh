#!/usr/bin/env bash
# Loopback wire-compat: Rust fips203_tunnel <-> C fips203_tunnel (TheMapleseed/203).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${TUNNEL_INTEROP_PORT:-19003}"
REF="${ROOT}/_ref-203"
C_BIN="${REF}/fips203_tunnel"
RUST_BIN=""
# Test-only PSK (64 hex chars) — not for production.
export TUNNEL_PSK_HEX="${TUNNEL_PSK_HEX:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
export TUNNEL_CLIENT_ID="${TUNNEL_CLIENT_ID:-interop_client}"
export TUNNEL_SERVER_ID="${TUNNEL_SERVER_ID:-interop_server}"
export TUNNEL_REKEY_INTERVAL="${TUNNEL_REKEY_INTERVAL:-1000000000}"

log() { printf '[interop] %s\n' "$*"; }
die() { printf '[interop] ERROR: %s\n' "$*" >&2; exit 1; }

ensure_c_binary() {
  if [[ -x "${C_BIN}" ]]; then
    return 0
  fi
  if [[ ! -d "${REF}" ]]; then
    die "Missing ${REF}. Clone: git clone --depth 1 https://github.com/TheMapleseed/203.git ${REF}"
  fi
  log "Building C fips203_tunnel in ${REF}..."
  make -C "${REF}" fips203_tunnel
  [[ -x "${C_BIN}" ]] || die "C build failed"
}

rust_target_dir() {
  if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
    printf '%s' "${CARGO_TARGET_DIR}"
  else
    printf '%s/target' "${ROOT}"
  fi
}

ensure_rust_binary() {
  local td
  td="$(rust_target_dir)"
  RUST_BIN="${td}/release/fips203_tunnel"
  if [[ ! -x "${RUST_BIN}" ]]; then
    log "Building Rust fips203_tunnel (release)..."
    (cd "${ROOT}" && cargo build -p fips203-tunnel --release)
  fi
  [[ -x "${RUST_BIN}" ]] || die "Rust build failed (expected ${RUST_BIN})"
}

wait_port_free() {
  local i
  for i in $(seq 1 30); do
    if ! nc -z 127.0.0.1 "${PORT}" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  die "port ${PORT} still in use"
}

run_case() (
  local name="$1"
  local server_cmd="$2"
  local client_cmd="$3"
  local srv_log cli_log srv_pid
  srv_log="$(mktemp)"
  cli_log="$(mktemp)"
  trap 'rm -f "${srv_log}" "${cli_log}"; kill ${srv_pid:-} 2>/dev/null || true' EXIT

  wait_port_free
  log "CASE ${name}: starting server on :${PORT}"
  bash -c "${server_cmd}" >"${srv_log}" 2>&1 &
  srv_pid=$!
  sleep 0.5

  log "CASE ${name}: running client"
  # Brief gap so the peer can echo before quit (C client recv thread vs stdin/tx).
  if ! bash -c "( echo hello; sleep 0.3; echo quit ) | ${client_cmd}" >"${cli_log}" 2>&1; then
    cat "${srv_log}" >&2
    cat "${cli_log}" >&2
    die "${name}: client exited non-zero"
  fi

  kill "${srv_pid}" 2>/dev/null || true
  wait "${srv_pid}" 2>/dev/null || true

  grep -q 'client: handshake complete' "${cli_log}" || {
    cat "${cli_log}" >&2
    die "${name}: client missing handshake complete"
  }
  grep -q 'client rx: hello' "${cli_log}" || {
    cat "${cli_log}" >&2
    die "${name}: client did not receive echoed hello"
  }
  grep -q 'server rx: hello' "${srv_log}" || {
    cat "${srv_log}" >&2
    die "${name}: server did not decode hello"
  }
  log "CASE ${name}: OK"
)

main() {
  ensure_c_binary
  ensure_rust_binary

  run_case "rust_client_c_server" \
    "${C_BIN} server ${PORT}" \
    "${RUST_BIN} client 127.0.0.1 ${PORT}"

  run_case "c_client_rust_server" \
    "${RUST_BIN} server ${PORT}" \
    "${C_BIN} client 127.0.0.1 ${PORT}"

  log "All interop cases passed."
}

main "$@"
