//! # fips203-core
//!
//! Pure-Rust, `std`-only implementation of [TheMapleseed/203](https://github.com/TheMapleseed/203):
//! **ML-KEM-768**, **FIPS203TUNNEL-GCM** records, PSK+KEM handshake, in-band rekey, and
//! MsgPack string helpers for ASCII lines.
//!
//! ## Example (record layer)
//!
//! ```no_run
//! use fips203_core::{frame_seal, frame_open, derive_tunnel_session, TunnelSession, pack_line};
//!
//! let mut session = TunnelSession::default();
//! // … after `tunnel::handshake_client` / `handshake_server` …
//!
//! let mut plain = [0u8; 64];
//! let n = pack_line(b"hello", &mut plain).unwrap();
//! let mut wire = [0u8; 4096];
//! let wl = frame_seal(&mut session, &plain[..n], &mut wire).unwrap();
//! let mut out = [0u8; 4096];
//! let ol = frame_open(&mut session, &wire[..wl], &mut out).unwrap();
//! assert_eq!(&out[..ol], &plain[..n]);
//! ```

mod error;
mod fips202;
mod frame;
mod mlkem;
mod msgpack;
mod secrets;
mod session;
pub mod tunnel;
mod wire;

pub use secrets::{protect_sensitive, release_sensitive, secret_zeroize, try_mlock, try_munlock};

pub use error::{Error, Result};
pub use frame::{
    derive_tunnel_session, frame_open, frame_seal, rekey_apply, TunnelSession, AAD_SIZE, MAX_FRAMES,
    MAX_MSG, MAX_WIRE, REKEY_NONCE_SIZE, SESSION_ID_SIZE, SESSION_PACKED_BYTES,
    SESSION_STATE_BYTES, TAG,
};
pub use session::SESSION_PACK_HEADER_U64;
pub use mlkem::{
    decaps, encaps, encaps_random, keygen, keygen_random, Ciphertext, DecapsKey, EncapsKey,
    SharedSecret, MLKEM768_CT_SIZE, MLKEM768_DK_SIZE, MLKEM768_EK_SIZE, MLKEM768_SS_SIZE,
    MLKEM_SEED_SIZE,
};
pub use msgpack::{
    ascii_valid, decode_string_only, decode_string_only_vec, format_decoded, pack_line,
    pack_line_vec, payload_is_quit,
};
pub use session::{session_pack, session_unpack};
pub use fips202::{sha3_256, shake256};

pub use tunnel::{
    build_control, ct_eq_32, fill_random, handshake_client, handshake_server, handshake_transcript,
    is_control, load_handshake_config_from_env, load_rekey_ack_timeout_secs_from_env,
    load_mlock_from_env, load_rekey_interval_from_env, load_wire_read_timeout_secs_from_env, mac32,
    open_plain,
    seal_plain, u32_be, wire_buffer, HandshakeConfig, TunnelRuntime, CTRL_ACK, CTRL_LEN,
    CTRL_MAGIC, CTRL_REQ, DEFAULT_REKEY_ACK_TIMEOUT_SECS, DEFAULT_REKEY_INTERVAL,
    DEFAULT_WIRE_READ_TIMEOUT_SECS, HS_TRANSCRIPT_BYTES, MAX_DECRYPT_FAILURES, PEER_ID_SIZE,
};
pub use wire::{read_wire_frame, write_wire_frame};
