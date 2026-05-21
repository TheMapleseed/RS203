//! Rust port of [TheMapleseed/203](https://github.com/TheMapleseed/203) crypto primitives.
//!
//! Wire-compatible **FIPS203TUNNEL-GCM** frames, **ML-KEM-768** (PQClean clean, pure Rust),
//! and **7-bit ASCII → MessagePack string** helpers match the C reference.

mod error;
mod fips202;
mod frame;
mod mlkem;
mod msgpack;
mod session;

pub use error::{Error, Result};
pub use frame::{
    frame_open, frame_seal, TunnelSession, AAD_SIZE, MAX_FRAMES, MAX_MSG, MAX_WIRE, SESSION_ID_SIZE,
    SESSION_STATE_BYTES, SESSION_PACKED_BYTES, TAG,
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
