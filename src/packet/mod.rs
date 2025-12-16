use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use bytes::BytesMut;
use proxy_protocol::{
    ProxyHeader,
    version2::{ProxyAddresses, ProxyCommand, ProxyTransportProtocol},
};
use valence_protocol::{
    Bounded, Decode, Encode, Packet, VarInt,
    packets::{
        handshaking::{HandshakeC2s, handshake_c2s::HandshakeNextState},
        login::LoginHelloC2s,
    },
    uuid::Uuid,
};

pub trait OwnedPacket<'a, P: Packet + Decode<'a> + Encode> {
    fn from_packet(packet: P) -> Self;
    fn as_packet(&'a self) -> P;
}

#[derive(Debug, Clone)]
/// Owned `HandshakeC2S`
pub struct OwnedHandshake {
    pub protocol_version: VarInt,
    pub server_address: Arc<str>,
    pub server_port: u16,
    pub next_state: HandshakeNextState,
}

impl OwnedHandshake {
    /// According to various spec including Forge
    pub fn get_stripped_hostname(&self) -> Arc<str> {
        const FALLBACK: &str = "unknown-host";
        let ptr = self
            .server_address
            .find('\0')
            .map(|nul| &self.server_address[..nul])
            .unwrap_or(self.server_address.as_ref());
        let sanitized: String = ptr
            .chars()
            .filter(|c| c.is_ascii() && !c.is_ascii_control())
            .take(255)
            .collect();
        if !sanitized.is_empty() {
            Arc::from(sanitized)
        } else {
            Arc::from(FALLBACK)
        }
    }
}

impl<'a> OwnedPacket<'a, HandshakeC2s<'a>> for OwnedHandshake {
    fn from_packet(hs: HandshakeC2s<'a>) -> Self {
        Self {
            protocol_version: hs.protocol_version,
            server_address: Arc::from(hs.server_address.0),
            server_port: hs.server_port,
            next_state: hs.next_state,
        }
    }
    fn as_packet(&'a self) -> HandshakeC2s<'a> {
        HandshakeC2s {
            protocol_version: self.protocol_version,
            server_address: Bounded(&self.server_address),
            server_port: self.server_port,
            next_state: self.next_state,
        }
    }
}

#[derive(Debug, Clone)]
/// Owned `LoginHelloC2S`
pub struct OwnedLoginHello {
    pub username: String,
    pub profile_id: Option<Uuid>,
}

impl<'a> OwnedPacket<'a, LoginHelloC2s<'a>> for OwnedLoginHello {
    fn from_packet(packet: LoginHelloC2s<'a>) -> Self {
        Self {
            username: packet.username.0.to_string(),
            profile_id: packet.profile_id,
        }
    }

    fn as_packet(&'a self) -> LoginHelloC2s<'a> {
        LoginHelloC2s {
            username: Bounded(&self.username),
            profile_id: self.profile_id,
        }
    }
}

pub fn create_proxy_protocol_header(socket: SocketAddr) -> anyhow::Result<BytesMut> {
    let proxy_header = ProxyHeader::Version2 {
        command: ProxyCommand::Proxy,
        transport_protocol: ProxyTransportProtocol::Stream,
        addresses: match socket {
            SocketAddr::V4(addr) => ProxyAddresses::Ipv4 {
                source: addr,
                destination: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            },
            SocketAddr::V6(addr) => ProxyAddresses::Ipv6 {
                source: addr,
                destination: SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0),
            },
        },
    };
    Ok(proxy_protocol::encode(proxy_header)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake_with_addr(addr: &str) -> OwnedHandshake {
        OwnedHandshake {
            protocol_version: VarInt(0),
            server_address: Arc::from(addr),
            server_port: 25565,
            next_state: HandshakeNextState::Login,
        }
    }

    #[test]
    fn stripped_hostname_stops_at_first_nul() {
        let hs = handshake_with_addr("example.com\0FML2\0");
        assert_eq!(hs.get_stripped_hostname().as_ref(), "example.com");

        let hs = handshake_with_addr("example.com\0FORGE\0");
        assert_eq!(hs.get_stripped_hostname().as_ref(), "example.com");
    }

    #[test]
    fn stripped_hostname_falls_back_on_empty() {
        let hs = handshake_with_addr("\0FML2\0");
        assert_eq!(hs.get_stripped_hostname().as_ref(), "unknown-host");
    }
}
