use std::{error::Error as StdError, fmt};

#[derive(Debug)]
pub enum Error {
    UnexpectedEof,
    InvalidVarInt,
    InvalidPacketId { expected: u32, actual: u32 },
    InvalidJwt,
    Utf8(std::str::Utf8Error),
    Json(serde_json::Error),
    Base64(base64::DecodeError),
    Snappy(snap::Error),
    Io(std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnexpectedEof => write!(f, "unexpected end of input"),
            Error::InvalidVarInt => write!(f, "invalid varint"),
            Error::InvalidPacketId { expected, actual } => {
                write!(f, "invalid packet id {actual:#x}, expected {expected:#x}")
            }
            Error::InvalidJwt => write!(f, "invalid jwt"),
            Error::Utf8(err) => write!(f, "utf-8 error: {err}"),
            Error::Json(err) => write!(f, "json error: {err}"),
            Error::Base64(err) => write!(f, "base64 error: {err}"),
            Error::Snappy(err) => write!(f, "snappy error: {err}"),
            Error::Io(err) => write!(f, "io error: {err}"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Utf8(err) => Some(err),
            Error::Json(err) => Some(err),
            Error::Base64(err) => Some(err),
            Error::Snappy(err) => Some(err),
            Error::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Self {
        Error::Utf8(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Json(err)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Error::Base64(err)
    }
}

impl From<snap::Error> for Error {
    fn from(err: snap::Error) -> Self {
        Error::Snappy(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}
