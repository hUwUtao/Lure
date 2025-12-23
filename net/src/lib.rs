//! Minimal Minecraft protocol types for handshake, status, and login start.
pub mod proto;

pub use proto::{
    HandshakeC2s, HandshakeNextState, LoginDisconnectS2c, LoginStartC2s, MAX_PACKET_SIZE,
    PacketDecode, PacketDecoder, PacketEncode, PacketEncoder, PacketFrame, PacketState, ProtoError,
    ServerboundPacket, StatusPingC2s, StatusPongS2c, StatusRequestC2s, StatusResponseS2c, Uuid,
    encode_packet,
};
