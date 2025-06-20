use std::sync::Arc;
use valence::uuid::Uuid;
use valence_protocol::packets::handshaking::handshake_c2s::HandshakeNextState;
use valence_protocol::packets::handshaking::HandshakeC2s;
use valence_protocol::{Bounded, Decode, Encode, Packet, VarInt};
use valence_protocol::packets::login::LoginHelloC2s;
use valence_protocol::packets::status::QueryResponseS2c;

pub trait OwnedPacket<'a, P: Packet + Decode<'a> + Encode> {
    fn from_packet(packet: P) -> Self;
    fn as_packet(&'a self) -> P;
}

#[derive(Debug, Clone)]
/// Owned `HandshakeC2S`
pub struct OwnedHandshake {
    pub protocol_version: VarInt,
    pub server_address: String,
    pub server_port: u16,
    pub next_state: HandshakeNextState,
}

impl<'a> OwnedPacket<'a, HandshakeC2s<'a>> for OwnedHandshake {
    fn from_packet(hs: HandshakeC2s<'a>) -> Self {
        Self {
            protocol_version: hs.protocol_version,
            server_address: hs.server_address.0.to_string(),
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
/// Owned `QueryResponseS2C`
pub struct OwnedQueryResponse {
    json: Arc<str>,
}

impl<'a> OwnedPacket<'a, QueryResponseS2c<'a>> for OwnedQueryResponse {
    fn from_packet(response: QueryResponseS2c) -> Self {
        Self {
            json: Arc::from(response.json),
        }
    }
    fn as_packet(&'a self) -> QueryResponseS2c<'a> {
        QueryResponseS2c { json: &self.json }
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
            profile_id: packet.profile_id
        }
    }

    fn as_packet(&'a self) -> LoginHelloC2s<'a> {
        LoginHelloC2s {
            username: Bounded(&self.username),
            profile_id: self.profile_id
        }
    }
}