use std::sync::Arc;

use net::{HandshakeC2s, HandshakeNextState, LoginStartC2s, LoginStartSigData, PacketEncode, Uuid};

pub trait OwnedPacket<'a, P> {
    fn from_packet(packet: P) -> Self;
    fn as_packet(&'a self) -> P;
}

#[derive(Debug, Clone)]
/// Owned `HandshakeC2S`
pub struct OwnedHandshake {
    pub protocol_version: i32,
    pub server_address: Arc<str>,
    pub server_port: u16,
    pub next_state: HandshakeNextState,
}

#[derive(Debug, Clone)]
pub struct OwnedLoginStart {
    pub username: Arc<str>,
    pub profile_id: Option<Uuid>,
    pub sig_data: Option<OwnedLoginSigData>,
}

#[derive(Debug, Clone)]
pub struct OwnedLoginSigData {
    pub timestamp: i64,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
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
            server_address: Arc::from(hs.server_address),
            server_port: hs.server_port,
            next_state: hs.next_state,
        }
    }
    fn as_packet(&'a self) -> HandshakeC2s<'a> {
        HandshakeC2s {
            protocol_version: self.protocol_version,
            server_address: &self.server_address,
            server_port: self.server_port,
            next_state: self.next_state,
        }
    }
}

impl<'a> OwnedPacket<'a, LoginStartC2s<'a>> for OwnedLoginStart {
    fn from_packet(packet: LoginStartC2s<'a>) -> Self {
        Self {
            username: Arc::from(packet.username),
            profile_id: packet.profile_id,
            sig_data: packet.sig_data.map(|sig| OwnedLoginSigData {
                timestamp: sig.timestamp,
                public_key: sig.public_key.to_vec(),
                signature: sig.signature.to_vec(),
            }),
        }
    }

    fn as_packet(&'a self) -> LoginStartC2s<'a> {
        LoginStartC2s {
            username: &self.username,
            profile_id: self.profile_id,
            sig_data: self.sig_data.as_ref().map(|sig| LoginStartSigData {
                timestamp: sig.timestamp,
                public_key: sig.public_key.as_slice(),
                signature: sig.signature.as_slice(),
            }),
        }
    }
}

pub fn encode_uncompressed_packet<P: PacketEncode>(packet: &P) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    net::encode_packet(&mut buf, packet)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake_with_addr(addr: &str) -> OwnedHandshake {
        OwnedHandshake {
            protocol_version: 0,
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
