use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::Destination;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelOpt {
    None,
    /// Explicit tunnel key_id in hex (8 bytes / 16 hex chars).
    KeyId([u8; 8]),
    /// Use the tenant's registered tunnel key for this route's zone.
    ZoneDefault,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    destination: Destination,
    tunnel: TunnelOpt,
}

impl Endpoint {
    pub fn new(destination: Destination, tunnel: TunnelOpt) -> Self {
        Self {
            destination,
            tunnel,
        }
    }

    pub fn destination(&self) -> &Destination {
        &self.destination
    }

    pub fn tunnel(&self) -> TunnelOpt {
        self.tunnel
    }

    pub fn parse(s: &str) -> Result<Self, ParseEndpointError> {
        let (dest, tunnel) = split_tunnel_suffix(s)?;
        let destination = Destination::parse(dest).map_err(ParseEndpointError::Destination)?;
        Ok(Self::new(destination, tunnel))
    }

    pub fn parse_with_default(s: &str, default_port: u16) -> Result<Self, ParseEndpointError> {
        let (dest, tunnel) = split_tunnel_suffix(s)?;
        let destination = Destination::parse_with_default(dest, default_port)
            .map_err(ParseEndpointError::Destination)?;
        Ok(Self::new(destination, tunnel))
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.tunnel {
            TunnelOpt::KeyId(id) => write!(f, "{}@{}", self.destination, hex::encode(id)),
            TunnelOpt::ZoneDefault => write!(f, "{}@tunnel-key", self.destination),
            TunnelOpt::None => write!(f, "{}", self.destination),
        }
    }
}

impl FromStr for Endpoint {
    type Err = ParseEndpointError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Endpoint::parse(s)
    }
}

impl Serialize for Endpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Endpoint::parse(&s).map_err(|err| serde::de::Error::custom(err.to_string()))
    }
}

#[derive(Debug)]
pub enum ParseEndpointError {
    Empty,
    Destination(super::dest::ParseDestinationError),
    InvalidTunnelId(String),
}

impl fmt::Display for ParseEndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseEndpointError::Empty => write!(f, "empty input"),
            ParseEndpointError::Destination(e) => write!(f, "{e}"),
            ParseEndpointError::InvalidTunnelId(e) => write!(f, "invalid tunnel-id: {e}"),
        }
    }
}

impl std::error::Error for ParseEndpointError {}

fn split_tunnel_suffix(s: &str) -> Result<(&str, TunnelOpt), ParseEndpointError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(ParseEndpointError::Empty);
    }

    let Some(at) = trimmed.rfind('@') else {
        return Ok((trimmed, TunnelOpt::None));
    };

    let dest = trimmed[..at].trim();
    let suffix = trimmed[at + 1..].trim();
    if dest.is_empty() {
        return Err(ParseEndpointError::Empty);
    }
    if suffix.is_empty() {
        return Err(ParseEndpointError::InvalidTunnelId(
            "missing tunnel selector after '@'".to_string(),
        ));
    }

    if suffix.eq_ignore_ascii_case("tunnel-key") {
        return Ok((dest, TunnelOpt::ZoneDefault));
    }

    if suffix.len() != 16 || !suffix.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ParseEndpointError::InvalidTunnelId(
            "expected 16 hex characters (8 bytes)".to_string(),
        ));
    }

    let mut out = [0u8; 8];
    for i in 0..8 {
        let byte = u8::from_str_radix(&suffix[i * 2..i * 2 + 2], 16).map_err(|e| {
            ParseEndpointError::InvalidTunnelId(format!("invalid hex at byte {i}: {e}"))
        })?;
        out[i] = byte;
    }

    Ok((dest, TunnelOpt::KeyId(out)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_without_tunnel_id() {
        let e = Endpoint::parse("example.com:25565").unwrap();
        assert_eq!(e.tunnel(), TunnelOpt::None);
        assert_eq!(e.to_string(), "example.com:25565");
    }

    #[test]
    fn parses_with_tunnel_id() {
        let e = Endpoint::parse("example.com:25565@0011223344556677").unwrap();
        assert_eq!(
            e.tunnel(),
            TunnelOpt::KeyId([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77])
        );
        assert_eq!(e.to_string(), "example.com:25565@0011223344556677");
    }

    #[test]
    fn parses_with_tunnel_key_selector() {
        let e = Endpoint::parse("example.com:25565@tunnel-key").unwrap();
        assert_eq!(e.tunnel(), TunnelOpt::ZoneDefault);
        assert_eq!(e.to_string(), "example.com:25565@tunnel-key");
    }

    #[test]
    fn rejects_empty_tunnel_id() {
        let err = Endpoint::parse("example.com:25565@").unwrap_err();
        assert!(err.to_string().contains("missing tunnel selector"));
    }
}
