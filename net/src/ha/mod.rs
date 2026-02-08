//! # `HAProxy` PROXY Protocol v2 Library
//!
//! This crate provides a lightweight, dependency-free implementation of the `HAProxy` PROXY protocol version 2 (`PPv2`),
//! including full support for address families, protocols, and standard Type-Length-Value (TLV) extensions.
//!
//! ## Overview
//! `PPv2` is a binary protocol used to convey client connection metadata through proxies. This library allows parsing
//! `PPv2` headers from byte slices and serializing them to byte vectors, adhering strictly to the specification.
//!
//! Key features:
//! - Zero-copy parsing where possible.
//! - Idiomatic Rust: Uses enums, matches, and immutable references extensively.
//! - Comprehensive error handling with descriptive variants.
//! - Support for all standard TLVs, with structured parsing for known types and raw bytes for unknowns.
//! - No external dependencies in production; optional dev-dependencies for testing.
//!
//! ## Usage
//! ### Parsing a Header
//! ```
//! use net::ha::{parse, Header, Error};
//!
//! const data: &[u8] = &[];
//! match parse(data) {
//!     Ok(header) => {
//!         // Access fields: header.command, header.family, etc.
//!     }
//!     Err(e) => {
//!         // Handle error
//!     }
//! }
//! ```
//!
//! ### Serializing a Header
//! ```rs,no_run
//! use std::net::{Ipv4Addr, SocketAddrV4};
//!
//! use net::ha::{AddressInfo, Command, Family, Header, Protocol, Tlv};
//!
//! # fn main() -> Result<(), net::ha::Error> {
//! let header = Header {
//!     command: Command::Proxy,
//!     family: Family::Inet,
//!     protocol: Protocol::Stream,
//!     address: AddressInfo::Ipv4(
//!         SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1234),
//!         SocketAddrV4::new(Ipv4Addr::LOCALHOST, 25565),
//!     ),
//!     tlvs: vec![Tlv::Authority("example.com".into())],
//! };
//! let bytes = header.serialize()?;
//! let _ = bytes;
//! # Ok(())
//! # }
//! ```
//!
//! ## Specification Summary
//! The `PPv2` header consists of:
//! - Fixed 12-byte signature: `\r\n\r\n\0\r\nQUIT\n` (0x0D0A0D0A000D0A515549540A).
//! - Version/Command byte: 0x20 for v2; low nibble 0x0 (LOCAL) or 0x1 (PROXY).
//! - Family/Protocol byte: High nibble for family (0x0 UNSPEC, 0x1 `AF_INET`, 0x2 `AF_INET6`, 0x3 `AF_UNIX`); low nibble for protocol (0x0 UNSPEC, 0x1 STREAM, 0x2 DGRAM).
//! - 16-bit length of address + TLVs (big-endian).
//! - Variable address block (0-216 bytes depending on family/protocol).
//! - Optional TLVs: 1-byte type, 2-byte length, variable value.
//!
//! ### Address Blocks
//! - UNSPEC/UNSPEC: 0 bytes.
//! - INET/STREAM or DGRAM: 12 bytes (src/dst IPv4 + ports).
//! - INET6/STREAM or DGRAM: 36 bytes (src/dst IPv6 + ports).
//! - UNIX/STREAM or DGRAM: 216 bytes (src/dst null-padded paths).
//!
//! ### Standard TLV Types
//! - 0x01 ALPN: UTF-8 string.
//! - 0x02 AUTHORITY: UTF-8 hostname.
//! - 0x03 CRC32C: 4-byte checksum (not enforced in this lib).
//! - 0x04 NOOP: Empty.
//! - 0x05 `UNIQUE_ID`: Bytes.
//! - 0x20 SSL: Structured (client flags, optional verify, sub-TLVs for version/CN/cipher/etc.).
//! - 0x30 NETNS: UTF-8 namespace.
//! - Unknown types are stored as raw bytes.
//!
//! ## Error Handling
//! Parsing returns `Result<Header, Error>`, where `Error` enumerates issues like invalid signatures, unsupported families, or parsing failures.
//!
//! ## Testing
//! Includes unit tests for core cases.
//!
//! For full spec details, refer to [HAProxy PROXY Protocol](https://www.haproxy.org/download/3.4/doc/proxy-protocol.txt).

use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    str::from_utf8,
};

/// Fixed signature for `PPv2` headers.
const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Command type: LOCAL (no proxy info) or PROXY (with info).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Local,
    Proxy,
}

/// Address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Unspec,
    Inet,
    Inet6,
    Unix,
}

/// Transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Unspec,
    Stream,
    Dgram,
}

/// Address information based on family and protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressInfo {
    None,
    Ipv4(SocketAddrV4, SocketAddrV4),
    Ipv6(SocketAddrV6, SocketAddrV6),
    Unix([u8; 108], [u8; 108]),
}

/// TLV variants, with structured data for known types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tlv {
    Alpn(Box<str>),
    Authority(Box<str>),
    Crc32c(u32),
    Noop,
    UniqueId(Box<[u8]>),
    Ssl {
        client: u8,
        verify: Option<u32>,
        version: Option<Box<str>>,
        cn: Option<Box<str>>,
        cipher: Option<Box<str>>,
        sig_alg: Option<Box<str>>,
        key_alg: Option<Box<str>>,
    },
    Netns(Box<str>),
    Unknown {
        type_code: u8,
        value: Box<[u8]>,
    },
}

/// Complete `PPv2` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub command: Command,
    pub family: Family,
    pub protocol: Protocol,
    pub address: AddressInfo,
    pub tlvs: Vec<Tlv>,
}

/// Errors during parsing or serialization.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    IncompleteData,
    InvalidSignature,
    InvalidVersion,
    UnsupportedCommand,
    UnsupportedFamilyProtocol,
    InvalidLength,
    ParseFailed(String),
    Utf8Error,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keep messages stable-ish; detailed context is usually in logs/call sites.
        match self {
            Self::IncompleteData => write!(f, "incomplete PPv2 header"),
            Self::InvalidSignature => write!(f, "invalid PPv2 signature"),
            Self::InvalidVersion => write!(f, "invalid PPv2 version"),
            Self::UnsupportedCommand => write!(f, "unsupported PPv2 command"),
            Self::UnsupportedFamilyProtocol => write!(f, "unsupported PPv2 family/protocol"),
            Self::InvalidLength => write!(f, "invalid PPv2 length"),
            Self::ParseFailed(msg) => write!(f, "PPv2 parse failed: {msg}"),
            Self::Utf8Error => write!(f, "PPv2 utf-8 error"),
        }
    }
}

impl std::error::Error for Error {}

impl Header {
    /// Serializes the header to a byte vector.
    #[must_use]
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let var_len = self.estimated_size();
        let mut buf = Vec::with_capacity(16 + var_len);

        buf.extend_from_slice(&SIGNATURE);

        let ver_cmd = 0x20u8
            | match self.command {
                Command::Local => 0x00,
                Command::Proxy => 0x01,
            };
        buf.push(ver_cmd);

        let fam_prot = (match self.family {
            Family::Unspec => 0x00,
            Family::Inet => 0x10,
            Family::Inet6 => 0x20,
            Family::Unix => 0x30,
        } | match self.protocol {
            Protocol::Unspec => 0x00,
            Protocol::Stream => 0x01,
            Protocol::Dgram => 0x02,
        });
        buf.push(fam_prot);

        let var_len_u16 = u16::try_from(var_len).map_err(|_| Error::InvalidLength)?;
        buf.extend_from_slice(&var_len_u16.to_be_bytes());
        self.append_address(&mut buf);

        for tlv in &self.tlvs {
            Self::append_tlv(&mut buf, tlv)?;
        }

        Ok(buf)
    }

    fn estimated_size(&self) -> usize {
        let addr_size = match self.address {
            AddressInfo::None => 0,
            AddressInfo::Ipv4(_, _) => 12,
            AddressInfo::Ipv6(_, _) => 36,
            AddressInfo::Unix(_, _) => 216,
        };
        let tlvs_size: usize = self.tlvs.iter().map(|tlv| 3 + tlv.value_size()).sum();
        addr_size + tlvs_size
    }

    fn append_address(&self, buf: &mut Vec<u8>) {
        match &self.address {
            AddressInfo::None => {}
            AddressInfo::Ipv4(src, dst) => {
                buf.extend_from_slice(&src.ip().octets());
                buf.extend_from_slice(&dst.ip().octets());
                buf.extend_from_slice(&src.port().to_be_bytes());
                buf.extend_from_slice(&dst.port().to_be_bytes());
            }
            AddressInfo::Ipv6(src, dst) => {
                buf.extend_from_slice(&src.ip().octets());
                buf.extend_from_slice(&dst.ip().octets());
                buf.extend_from_slice(&src.port().to_be_bytes());
                buf.extend_from_slice(&dst.port().to_be_bytes());
            }
            AddressInfo::Unix(src_path, dst_path) => {
                buf.extend_from_slice(src_path);
                buf.extend_from_slice(dst_path);
            }
        }
    }

    fn append_raw_tlv(buf: &mut Vec<u8>, type_code: u8, value: &[u8]) -> Result<(), Error> {
        buf.push(type_code);
        let len_u16 = u16::try_from(value.len()).map_err(|_| Error::InvalidLength)?;
        buf.extend_from_slice(&len_u16.to_be_bytes());
        buf.extend_from_slice(value);
        Ok(())
    }

    fn append_str_tlv(buf: &mut Vec<u8>, type_code: u8, value: &str) -> Result<(), Error> {
        Self::append_raw_tlv(buf, type_code, value.as_bytes())
    }

    fn append_tlv(buf: &mut Vec<u8>, tlv: &Tlv) -> Result<(), Error> {
        match tlv {
            Tlv::Alpn(s) => Self::append_str_tlv(buf, 0x01, s),
            Tlv::Authority(s) => Self::append_str_tlv(buf, 0x02, s),
            Tlv::Crc32c(c) => Self::append_raw_tlv(buf, 0x03, &c.to_be_bytes()),
            Tlv::Noop => Self::append_raw_tlv(buf, 0x04, &[]),
            Tlv::UniqueId(v) => Self::append_raw_tlv(buf, 0x05, v),
            Tlv::Ssl {
                client,
                verify,
                version,
                cn,
                cipher,
                sig_alg,
                key_alg,
            } => {
                buf.push(0x20);
                let len_u16 = u16::try_from(tlv.value_size()).map_err(|_| Error::InvalidLength)?;
                buf.extend_from_slice(&len_u16.to_be_bytes());
                buf.push(*client);
                if let Some(v) = verify {
                    buf.extend_from_slice(&v.to_be_bytes());
                }
                if let Some(s) = version.as_deref() {
                    Self::append_str_tlv(buf, 0x21, s)?;
                }
                if let Some(s) = cn.as_deref() {
                    Self::append_str_tlv(buf, 0x22, s)?;
                }
                if let Some(s) = cipher.as_deref() {
                    Self::append_str_tlv(buf, 0x23, s)?;
                }
                if let Some(s) = sig_alg.as_deref() {
                    Self::append_str_tlv(buf, 0x24, s)?;
                }
                if let Some(s) = key_alg.as_deref() {
                    Self::append_str_tlv(buf, 0x25, s)?;
                }
                Ok(())
            }
            Tlv::Netns(s) => Self::append_str_tlv(buf, 0x30, s),
            Tlv::Unknown { type_code, value } => Self::append_raw_tlv(buf, *type_code, value),
        }
    }
}

impl Tlv {
    fn value_size(&self) -> usize {
        match self {
            Self::Alpn(s) | Self::Authority(s) | Self::Netns(s) => s.len(),
            Self::Crc32c(_) => 4,
            Self::Noop => 0,
            Self::UniqueId(v) | Self::Unknown { value: v, .. } => v.len(),
            Self::Ssl {
                verify,
                version,
                cn,
                cipher,
                sig_alg,
                key_alg,
                ..
            } => {
                1 + verify.map_or(0, |_| 4)
                    + version.as_ref().map_or(0, |s| 3 + s.len())
                    + cn.as_ref().map_or(0, |s| 3 + s.len())
                    + cipher.as_ref().map_or(0, |s| 3 + s.len())
                    + sig_alg.as_ref().map_or(0, |s| 3 + s.len())
                    + key_alg.as_ref().map_or(0, |s| 3 + s.len())
            }
        }
    }
}

/// Parses a `PPv2` header from a byte slice.
pub fn parse(data: &[u8]) -> Result<Header, Error> {
    if data.len() < 16 {
        return Err(Error::IncompleteData);
    }

    if data[0..12] != SIGNATURE {
        return Err(Error::InvalidSignature);
    }

    let ver_cmd = data[12];
    if ver_cmd & 0xF0 != 0x20 {
        return Err(Error::InvalidVersion);
    }

    let command = match ver_cmd & 0x0F {
        0x00 => Command::Local,
        0x01 => Command::Proxy,
        _ => return Err(Error::UnsupportedCommand),
    };

    let fam_prot = data[13];
    let family = match fam_prot & 0xF0 {
        0x00 => Family::Unspec,
        0x10 => Family::Inet,
        0x20 => Family::Inet6,
        0x30 => Family::Unix,
        _ => return Err(Error::UnsupportedFamilyProtocol),
    };

    let protocol = match fam_prot & 0x0F {
        0x00 => Protocol::Unspec,
        0x01 => Protocol::Stream,
        0x02 => Protocol::Dgram,
        _ => return Err(Error::UnsupportedFamilyProtocol),
    };

    let var_len = u16::from_be_bytes([data[14], data[15]]) as usize;
    if data.len() != 16 + var_len {
        return Err(Error::InvalidLength);
    }

    let var_data = &data[16..];

    let expected_addr_len = match (family, protocol) {
        (Family::Unspec, Protocol::Unspec) => 0,
        (Family::Inet, Protocol::Stream | Protocol::Dgram) => 12,
        (Family::Inet6, Protocol::Stream | Protocol::Dgram) => 36,
        (Family::Unix, Protocol::Stream | Protocol::Dgram) => 216,
        _ => return Err(Error::UnsupportedFamilyProtocol),
    };

    if var_data.len() < expected_addr_len {
        return Err(Error::InvalidLength);
    }

    let address = parse_address(family, protocol, &var_data[0..expected_addr_len])?;

    let tlv_data = &var_data[expected_addr_len..];
    let tlvs = parse_tlvs(tlv_data)?;

    Ok(Header {
        command,
        family,
        protocol,
        address,
        tlvs,
    })
}

fn parse_address(family: Family, protocol: Protocol, data: &[u8]) -> Result<AddressInfo, Error> {
    match (family, protocol) {
        (Family::Unspec, Protocol::Unspec) => Ok(AddressInfo::None),
        (Family::Inet, _) => {
            let src_ip = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
            let dst_ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            let src_port = u16::from_be_bytes([data[8], data[9]]);
            let dst_port = u16::from_be_bytes([data[10], data[11]]);
            Ok(AddressInfo::Ipv4(
                SocketAddrV4::new(src_ip, src_port),
                SocketAddrV4::new(dst_ip, dst_port),
            ))
        }
        (Family::Inet6, _) => {
            let src_ip = Ipv6Addr::from(
                <[u8; 16]>::try_from(&data[0..16])
                    .map_err(|_| Error::ParseFailed("Invalid IPv6 slice".to_string()))?,
            );
            let dst_ip = Ipv6Addr::from(
                <[u8; 16]>::try_from(&data[16..32])
                    .map_err(|_| Error::ParseFailed("Invalid IPv6 slice".to_string()))?,
            );
            let src_port = u16::from_be_bytes([data[32], data[33]]);
            let dst_port = u16::from_be_bytes([data[34], data[35]]);
            Ok(AddressInfo::Ipv6(
                SocketAddrV6::new(src_ip, src_port, 0, 0),
                SocketAddrV6::new(dst_ip, dst_port, 0, 0),
            ))
        }
        (Family::Unix, _) => {
            let src_path = <[u8; 108]>::try_from(&data[0..108])
                .map_err(|_| Error::ParseFailed("Invalid UNIX path slice".to_string()))?;
            let dst_path = <[u8; 108]>::try_from(&data[108..216])
                .map_err(|_| Error::ParseFailed("Invalid UNIX path slice".to_string()))?;
            Ok(AddressInfo::Unix(src_path, dst_path))
        }
        _ => Err(Error::UnsupportedFamilyProtocol),
    }
}

fn parse_tlvs(mut data: &[u8]) -> Result<Vec<Tlv>, Error> {
    let mut tlvs = Vec::new();
    while !data.is_empty() {
        if data.len() < 3 {
            return Err(Error::IncompleteData);
        }
        let type_code = data[0];
        let len = u16::from_be_bytes([data[1], data[2]]) as usize;
        if data.len() < 3 + len {
            return Err(Error::InvalidLength);
        }
        let value = &data[3..3 + len];
        let tlv = match type_code {
            0x01 => Tlv::Alpn(parse_utf8(value)?),
            0x02 => Tlv::Authority(parse_utf8(value)?),
            0x03 if len == 4 => Tlv::Crc32c(u32::from_be_bytes(
                <[u8; 4]>::try_from(value)
                    .map_err(|_| Error::ParseFailed("Invalid CRC32C".to_string()))?,
            )),
            0x04 if len == 0 => Tlv::Noop,
            0x05 => Tlv::UniqueId(value.to_vec().into_boxed_slice()),
            0x20 => parse_ssl_tlv(value)?,
            0x30 => Tlv::Netns(parse_utf8(value)?),
            _ => Tlv::Unknown {
                type_code,
                value: value.to_vec().into_boxed_slice(),
            },
        };
        tlvs.push(tlv);
        data = &data[3 + len..];
    }
    Ok(tlvs)
}

fn parse_ssl_tlv(value: &[u8]) -> Result<Tlv, Error> {
    if value.is_empty() {
        return Err(Error::ParseFailed("Empty SSL TLV".to_string()));
    }
    let client = value[0];
    let mut offset = 1;
    let verify = if client & 0x01 != 0 {
        if value.len() < offset + 4 {
            return Err(Error::InvalidLength);
        }
        let v = u32::from_be_bytes([
            value[offset],
            value[offset + 1],
            value[offset + 2],
            value[offset + 3],
        ]);
        offset += 4;
        Some(v)
    } else {
        None
    };

    let sub_data = &value[offset..];
    let mut version = None;
    let mut cn = None;
    let mut cipher = None;
    let mut sig_alg = None;
    let mut key_alg = None;

    let mut sub_offset = 0;
    while sub_offset < sub_data.len() {
        if sub_data.len() - sub_offset < 3 {
            break; // Skip incomplete sub-TLVs
        }
        let sub_type = sub_data[sub_offset];
        let sub_len =
            u16::from_be_bytes([sub_data[sub_offset + 1], sub_data[sub_offset + 2]]) as usize;
        sub_offset += 3;
        if sub_offset + sub_len > sub_data.len() {
            break;
        }
        let sub_value = &sub_data[sub_offset..sub_offset + sub_len];
        match sub_type {
            0x21 => version = Some(parse_utf8(sub_value)?),
            0x22 => cn = Some(parse_utf8(sub_value)?),
            0x23 => cipher = Some(parse_utf8(sub_value)?),
            0x24 => sig_alg = Some(parse_utf8(sub_value)?),
            0x25 => key_alg = Some(parse_utf8(sub_value)?),
            _ => {} // Ignore unknown sub-TLVs
        }
        sub_offset += sub_len;
    }

    Ok(Tlv::Ssl {
        client,
        verify,
        version,
        cn,
        cipher,
        sig_alg,
        key_alg,
    })
}

fn parse_utf8(value: &[u8]) -> Result<Box<str>, Error> {
    Ok(from_utf8(value)
        .map_err(|_| Error::Utf8Error)?
        .to_owned()
        .into_boxed_str())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::*;

    #[test]
    fn test_parse_ipv4_basic() {
        let mut data = vec![];
        data.extend_from_slice(&SIGNATURE);
        data.push(0x21); // v2, Proxy
        data.push(0x11); // Inet, Stream
        data.extend_from_slice(&12u16.to_be_bytes());
        data.extend_from_slice(&[192, 168, 1, 1]); // src ip
        data.extend_from_slice(&[192, 168, 1, 2]); // dst ip
        data.extend_from_slice(&8080u16.to_be_bytes()); // src port
        data.extend_from_slice(&80u16.to_be_bytes()); // dst port

        let header = parse(&data).unwrap();
        assert_eq!(header.command, Command::Proxy);
        assert_eq!(header.family, Family::Inet);
        assert_eq!(header.protocol, Protocol::Stream);
        match header.address {
            AddressInfo::Ipv4(src, dst) => {
                assert_eq!(src.ip(), &Ipv4Addr::new(192, 168, 1, 1));
                assert_eq!(src.port(), 8080);
                assert_eq!(dst.ip(), &Ipv4Addr::new(192, 168, 1, 2));
                assert_eq!(dst.port(), 80);
            }
            _ => panic!("Wrong address type"),
        }
        assert!(header.tlvs.is_empty());
    }

    #[test]
    fn test_roundtrip_with_tlv() {
        let original = Header {
            command: Command::Proxy,
            family: Family::Inet,
            protocol: Protocol::Stream,
            address: AddressInfo::Ipv4(
                SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1234),
                SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 5678),
            ),
            tlvs: vec![Tlv::Alpn("http/1.1".into())],
        };
        let bytes = original.serialize().unwrap();
        let parsed = parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }
}
