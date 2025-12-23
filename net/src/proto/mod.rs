//! Minimal Minecraft protocol framing for handshake, status, and login start.

mod error;
mod io;
mod packets;
mod state;
mod types;
mod varint;

#[cfg(test)]
mod tests;

pub use error::{ProtoError, Result};
pub use packets::{
    HandshakeC2s, LoginDisconnectS2c, LoginStartC2s, ServerboundPacket, StatusPingC2s,
    StatusPongS2c, StatusRequestC2s, StatusResponseS2c,
};
pub use state::{HandshakeNextState, PacketState};
pub use types::{
    encode_packet, PacketDecode, PacketDecoder, PacketEncoder, PacketEncode, PacketFrame, Uuid,
    MAX_PACKET_SIZE,
};
