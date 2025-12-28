use std::fmt;

use super::state::PacketState;

/// Protocol decode/encode error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    UnexpectedEof,
    VarIntTooLarge,
    PacketTooLarge { len: usize },
    NegativeLength(i32),
    InvalidBool(u8),
    InvalidUtf8,
    StringTooLong { max: usize, actual: usize },
    LengthTooLarge { max: usize, actual: usize },
    TrailingBytes(usize),
    MissingField(&'static str),
    InvalidPacketId { state: PacketState, id: i32 },
    InvalidHandshakeState(i32),
}

pub type Result<T> = std::result::Result<T, ProtoError>;

pub(crate) fn debug_log_error(context: &str, error: &ProtoError) {
    #[cfg(debug_assertions)]
    {
        log::error!("{}: {:?}", context, error);
    }
    let _ = context;
    let _ = error;
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for ProtoError {}
