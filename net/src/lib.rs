//! # `net`-code
//! A minimal, dependency-free-ish netcodes to run a minecraft reverse proxy.
//! With sufficient amount of implemented parser and encoder, it is still light and pretty much served perfectly for this case.
//!
//! - `net::ha` - HA-Proxy Protocol: For authentication, session pre-tagging.
//! - `net::mc` - Minecraft Protocol: For native handshake, status, etc.
pub mod ha;
pub mod mc;

pub use ha::{AddressInfo, Command, Family, Header, Protocol, Tlv, parse};
pub use mc::{
    HandshakeC2s, HandshakeNextState, LoginDisconnectS2c, LoginStartC2s, MAX_PACKET_SIZE,
    PacketDecode, PacketDecoder, PacketEncode, PacketEncoder, PacketFrame, PacketState, ProtoError,
    ServerboundPacket, StatusPingC2s, StatusPongS2c, StatusRequestC2s, StatusResponseS2c, Uuid,
    encode_packet,
};
