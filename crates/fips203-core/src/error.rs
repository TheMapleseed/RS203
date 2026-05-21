#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidArgument,
    BufferTooSmall,
    Length,
    Crypto,
    NotAscii,
    MsgPack,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidArgument => write!(f, "invalid argument"),
            Error::BufferTooSmall => write!(f, "buffer too small"),
            Error::Length => write!(f, "plaintext or wire length out of range"),
            Error::Crypto => write!(f, "cryptographic verification failed"),
            Error::NotAscii => write!(f, "not 7-bit ASCII"),
            Error::MsgPack => write!(f, "MessagePack encode/decode failed"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
