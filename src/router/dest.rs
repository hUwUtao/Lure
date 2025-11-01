use std::{
    error::Error as StdError,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    str::FromStr,
    sync::Arc,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    IPV4(Ipv4Addr),
    IPV6(Ipv6Addr),
    FQDN(Arc<str>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination(Address, u16);

impl Destination {
    pub fn new(address: Address, port: u16) -> Self {
        Destination(address, port)
    }

    /// Parse a destination from a string that MUST contain a port.
    ///
    /// Supported forms:
    /// - IPv4 with port: `1.2.3.4:8080`
    /// - FQDN with port: `example.com:443`
    /// - IPv6 with port (bracketed): `[::1]:8080`
    ///
    /// Unbracketed IPv6 with an explicit port is rejected.
    pub fn parse(s: &str) -> Result<Self, ParseDestinationError> {
        parse_mandatory_port(s)
    }

    /// Parse a destination from a string that MAY omit the port.
    ///
    /// If the port is missing the provided `default_port` is used.
    ///
    /// Rules:
    /// - Bracketed IPv6 may include a port: `[::1]:8080` or just `[::1]`.
    /// - If the input contains exactly one `:` it is treated as `host:port`.
    /// - If the input contains more than one `:` and is not bracketed it is treated as an IPv6 address with no port.
    /// - Otherwise if no port is present the default is used.
    pub fn parse_with_default(s: &str, default_port: u16) -> Result<Self, ParseDestinationError> {
        parse_with_default_port(s, default_port)
    }

    pub fn address(&self) -> &Address {
        &self.0
    }

    pub fn port(&self) -> u16 {
        self.1
    }

    pub fn resolve(&self) -> Result<Vec<(Arc<str>, SocketAddr)>, ParseDestinationError> {
        match &self.0 {
            Address::IPV4(v4) => {
                // Ipv4Addr is Copy. Convert its textual form into Arc<str> without extra clones.
                let host = Arc::from(v4.to_string().into_boxed_str());
                let sa = SocketAddr::new(IpAddr::V4(*v4), self.1);
                Ok(vec![(host, sa)])
            }
            Address::IPV6(v6) => {
                let host = Arc::from(v6.to_string().into_boxed_str());
                let sa = SocketAddr::new(IpAddr::V6(*v6), self.1);
                Ok(vec![(host, sa)])
            }
            Address::FQDN(s) => {
                let addrs = (s.as_ref(), self.1)
                    .to_socket_addrs()
                    .map_err(ParseDestinationError::ResolveError)?;
                Ok(addrs.map(|sa| (s.clone(), sa)).collect())
            }
        }
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Address::IPV4(v4) => write!(f, "{}:{}", v4, self.1),
            Address::IPV6(v6) => write!(f, "[{}]:{}", v6, self.1),
            Address::FQDN(s) => write!(f, "{}:{}", s, self.1),
        }
    }
}

impl Default for Destination {
    fn default() -> Self {
        Destination(Address::IPV4(Ipv4Addr::UNSPECIFIED), 0)
    }
}

#[derive(Debug)]
pub enum ParseDestinationError {
    Empty,
    MissingPort,
    InvalidPort(std::num::ParseIntError),
    InvalidIpv4(std::net::AddrParseError),
    InvalidIpv6(std::net::AddrParseError),
    MissingClosingBracket,
    Ipv6RequiresBrackets,
    ResolveError(std::io::Error),
}

impl fmt::Display for ParseDestinationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ParseDestinationError::*;
        match self {
            Empty => write!(f, "empty input"),
            MissingPort => write!(f, "missing port"),
            InvalidPort(e) => write!(f, "invalid port: {}", e),
            InvalidIpv4(e) => write!(f, "invalid IPv4 address: {}", e),
            InvalidIpv6(e) => write!(f, "invalid IPv6 address: {}", e),
            MissingClosingBracket => write!(f, "missing closing ']' for IPv6 literal"),
            Ipv6RequiresBrackets => write!(
                f,
                "IPv6 address with port must be bracketed, e.g. [::1]:8080"
            ),
            ResolveError(e) => write!(f, "failed to resolve hostname: {}", e),
        }
    }
}

impl StdError for ParseDestinationError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            ParseDestinationError::InvalidPort(e) => Some(e),
            ParseDestinationError::InvalidIpv4(e) => Some(e),
            ParseDestinationError::InvalidIpv6(e) => Some(e),
            _ => None,
        }
    }
}

// Helpers

fn parse_mandatory_port(s: &str) -> Result<Destination, ParseDestinationError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ParseDestinationError::Empty);
    }

    // bracketed IPv6 form: [addr]:port
    if s.starts_with('[') {
        let close = s
            .find(']')
            .ok_or(ParseDestinationError::MissingClosingBracket)?;
        let host = &s[1..close];
        let rest = &s[close + 1..];
        if !rest.starts_with(':') {
            return Err(ParseDestinationError::MissingPort);
        }
        let port_str = &rest[1..];
        let port = port_str
            .parse::<u16>()
            .map_err(ParseDestinationError::InvalidPort)?;
        let addr = parse_host_as_address(host)?;
        return Ok(Destination::new(addr, port));
    }

    // otherwise split on last ':' and ensure left side is not an IPv6 literal (contains ':')
    if let Some(idx) = s.rfind(':') {
        let left = &s[..idx];
        let right = &s[idx + 1..];
        if left.contains(':') {
            // this is something like "2001:db8::1:8080" which is ambiguous.
            return Err(ParseDestinationError::Ipv6RequiresBrackets);
        }
        let port = right
            .parse::<u16>()
            .map_err(ParseDestinationError::InvalidPort)?;
        let addr = parse_host_as_address(left)?;
        return Ok(Destination::new(addr, port));
    }

    Err(ParseDestinationError::MissingPort)
}

fn parse_with_default_port(
    s: &str,
    default_port: u16,
) -> Result<Destination, ParseDestinationError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ParseDestinationError::Empty);
    }

    // bracketed IPv6 may include port or not: [::1]:8080 or [::1]
    if s.starts_with('[') {
        let close = s
            .find(']')
            .ok_or(ParseDestinationError::MissingClosingBracket)?;
        let host = &s[1..close];
        let rest = &s[close + 1..];
        let port = if rest.is_empty() {
            default_port
        } else {
            if !rest.starts_with(':') {
                // something like "[::1]foo" -> invalid
                return Err(ParseDestinationError::MissingPort);
            }
            rest[1..]
                .parse::<u16>()
                .map_err(ParseDestinationError::InvalidPort)?
        };
        let addr = parse_host_as_address(host)?;
        return Ok(Destination::new(addr, port));
    }

    // Count colons to disambiguate IPv6 vs host:port
    let colon_count = s.matches(':').count();

    if colon_count == 0 {
        // no port
        let addr = parse_host_as_address(s)?;
        return Ok(Destination::new(addr, default_port));
    }

    if colon_count == 1 {
        // treat as host:port
        if let Some(idx) = s.rfind(':') {
            let left = &s[..idx];
            let right = &s[idx + 1..];
            // left may be IPv4 or FQDN
            let port = right
                .parse::<u16>()
                .map_err(ParseDestinationError::InvalidPort)?;
            let addr = parse_host_as_address(left)?;
            return Ok(Destination::new(addr, port));
        }
    }

    // colon_count > 1 and not bracketed -> treat as IPv6 literal with no port
    let addr = parse_host_as_address(s)?;
    Ok(Destination::new(addr, default_port))
}

fn parse_host_as_address(host: &str) -> Result<Address, ParseDestinationError> {
    let host = host.trim();
    if host.is_empty() {
        return Err(ParseDestinationError::Empty);
    }

    // Try IPv4
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return Ok(Address::IPV4(v4));
    }

    // Try IPv6
    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        return Ok(Address::IPV6(v6));
    }

    // Fallback to FQDN. We keep it raw. Caller can validate further if needed.
    Ok(Address::FQDN(Arc::from(host.to_string())))
}

impl FromStr for Destination {
    type Err = ParseDestinationError;

    /// FromStr expects the input to include a port.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Destination::parse(s)
    }
}

impl Serialize for Destination {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Destination {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Destination::parse(&s).map_err(|err| serde::de::Error::custom(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_with_port() {
        let d = Destination::parse("1.2.3.4:8080").unwrap();
        match d.address() {
            Address::IPV4(ip) => assert_eq!(*ip, Ipv4Addr::new(1, 2, 3, 4)),
            _ => panic!("expected ipv4"),
        }
        assert_eq!(d.port(), 8080);
    }

    #[test]
    fn parse_fqdn_with_port() {
        let d = Destination::parse("example.com:443").unwrap();
        match d.address() {
            Address::FQDN(s) => assert_eq!(s.as_ref(), "example.com"),
            _ => panic!("expected fqdn"),
        }
        assert_eq!(d.port(), 443);
    }

    #[test]
    fn parse_ipv6_bracketed_with_port() {
        let d = Destination::parse("[::1]:8080").unwrap();
        match d.address() {
            Address::IPV6(ip) => assert_eq!(*ip, Ipv6Addr::from_str("::1").unwrap()),
            _ => panic!("expected ipv6"),
        }
        assert_eq!(d.port(), 8080);
    }

    #[test]
    fn parse_with_default_ipv4() {
        let d = Destination::parse_with_default("1.2.3.4", 80).unwrap();
        match d.address() {
            Address::IPV4(ip) => assert_eq!(*ip, Ipv4Addr::new(1, 2, 3, 4)),
            _ => panic!("expected ipv4"),
        }
        assert_eq!(d.port(), 80);
    }

    #[test]
    fn parse_with_default_ipv6_unbracketed() {
        let d = Destination::parse_with_default("2001:db8::1", 1234).unwrap();
        match d.address() {
            Address::IPV6(ip) => assert_eq!(*ip, Ipv6Addr::from_str("2001:db8::1").unwrap()),
            _ => panic!("expected ipv6"),
        }
        assert_eq!(d.port(), 1234);
    }

    #[test]
    fn parse_with_default_ipv6_bracketed_no_port() {
        let d = Destination::parse_with_default("[2001:db8::1]", 9000).unwrap();
        match d.address() {
            Address::IPV6(ip) => assert_eq!(*ip, Ipv6Addr::from_str("2001:db8::1").unwrap()),
            _ => panic!("expected ipv6"),
        }
        assert_eq!(d.port(), 9000);
    }

    #[test]
    fn reject_unbracketed_ipv6_with_port() {
        let e = Destination::parse("2001:db8::1:8080").unwrap_err();
        match e {
            ParseDestinationError::Ipv6RequiresBrackets => {}
            _ => panic!("expected Ipv6RequiresBrackets"),
        }
    }

    #[test]
    fn display_formats() {
        let d1 = Destination::parse("example.com:123").unwrap();
        assert_eq!(d1.to_string(), "example.com:123");

        let d2 = Destination::parse("[::1]:80").unwrap();
        assert_eq!(d2.to_string(), "[::1]:80");

        let d3 = Destination::parse("127.0.0.1:9").unwrap();
        assert_eq!(d3.to_string(), "127.0.0.1:9");
    }
}
