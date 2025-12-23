use super::{
    error::{ProtoError, Result, debug_log_error},
    io::{
        read_bool, read_i64_be, read_string_bounded, read_u16_be, read_uuid, write_bool,
        write_i64_be, write_string_bounded, write_u16_be, write_uuid,
    },
    state::{HandshakeNextState, PacketState},
    types::{PacketDecode, PacketEncode, PacketFrame, Uuid},
    varint::{read_varint, write_varint},
};

/// Handshake (C2S) packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeC2s<'a> {
    pub protocol_version: i32,
    pub server_address: &'a str,
    pub server_port: u16,
    pub next_state: HandshakeNextState,
}

/// Status request (C2S) packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusRequestC2s;

/// Status ping (C2S) packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusPingC2s {
    pub payload: i64,
}

/// Status response (S2C) packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusResponseS2c<'a> {
    pub json: &'a str,
}

/// Status pong (S2C) packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusPongS2c {
    pub payload: i64,
}

/// Login disconnect (S2C) packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginDisconnectS2c<'a> {
    pub reason: &'a str,
}

/// Login start (C2S) packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginStartC2s<'a> {
    pub username: &'a str,
    pub profile_id: Option<Uuid>,
}

/// Any serverbound packet supported by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerboundPacket<'a> {
    Handshake(HandshakeC2s<'a>),
    StatusRequest(StatusRequestC2s),
    StatusPing(StatusPingC2s),
    LoginStart(LoginStartC2s<'a>),
}

impl PacketFrame {
    pub fn decode_serverbound<'a>(&'a self, state: PacketState) -> Result<ServerboundPacket<'a>> {
        ServerboundPacket::decode(state, self)
    }
}

impl<'a> ServerboundPacket<'a> {
    pub fn decode(state: PacketState, frame: &'a PacketFrame) -> Result<Self> {
        let mut input = frame.body.as_slice();
        let packet = match state {
            PacketState::Handshaking => {
                if frame.id != HandshakeC2s::ID {
                    return Err(ProtoError::InvalidPacketId {
                        state,
                        id: frame.id,
                    });
                }
                HandshakeC2s::decode_body(&mut input).map(ServerboundPacket::Handshake)
            }
            PacketState::Status => match frame.id {
                StatusRequestC2s::ID => {
                    StatusRequestC2s::decode_body(&mut input).map(ServerboundPacket::StatusRequest)
                }
                StatusPingC2s::ID => {
                    StatusPingC2s::decode_body(&mut input).map(ServerboundPacket::StatusPing)
                }
                _ => Err(ProtoError::InvalidPacketId {
                    state,
                    id: frame.id,
                }),
            },
            PacketState::Login => match frame.id {
                LoginStartC2s::ID => {
                    LoginStartC2s::decode_body(&mut input).map(ServerboundPacket::LoginStart)
                }
                _ => Err(ProtoError::InvalidPacketId {
                    state,
                    id: frame.id,
                }),
            },
        };

        let packet = match packet {
            Ok(value) => value,
            Err(err) => {
                debug_log_error("packet body decode failed", &err);
                return Err(err);
            }
        };

        if !input.is_empty() {
            let err = ProtoError::TrailingBytes(input.len());
            debug_log_error("packet had trailing bytes", &err);
            return Err(err);
        }

        Ok(packet)
    }
}

impl<'a> HandshakeC2s<'a> {
    pub const ID: i32 = 0x00;

    pub fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        let protocol_version = read_varint(input)?;
        let server_address = read_string_bounded(input, 255)?;
        let server_port = read_u16_be(input)?;
        let next_state_raw = read_varint(input)?;
        let next_state = match next_state_raw {
            1 => HandshakeNextState::Status,
            2 => HandshakeNextState::Login,
            other => return Err(ProtoError::InvalidHandshakeState(other)),
        };

        Ok(Self {
            protocol_version,
            server_address,
            server_port,
            next_state,
        })
    }
}

impl<'a> PacketDecode<'a> for HandshakeC2s<'a> {
    const ID: i32 = HandshakeC2s::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        HandshakeC2s::decode_body(input)
    }
}

impl<'a> PacketEncode for HandshakeC2s<'a> {
    const ID: i32 = HandshakeC2s::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        write_varint(out, self.protocol_version);
        write_string_bounded(out, self.server_address, 255)?;
        write_u16_be(out, self.server_port);
        let next = match self.next_state {
            HandshakeNextState::Status => 1,
            HandshakeNextState::Login => 2,
        };
        write_varint(out, next);
        Ok(())
    }
}

impl StatusRequestC2s {
    pub const ID: i32 = 0x00;

    pub fn decode_body(_input: &mut &[u8]) -> Result<Self> {
        Ok(Self)
    }
}

impl<'a> PacketDecode<'a> for StatusRequestC2s {
    const ID: i32 = StatusRequestC2s::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        StatusRequestC2s::decode_body(input)
    }
}

impl PacketEncode for StatusRequestC2s {
    const ID: i32 = StatusRequestC2s::ID;

    fn encode_body(&self, _out: &mut Vec<u8>) -> Result<()> {
        Ok(())
    }
}

impl StatusPingC2s {
    pub const ID: i32 = 0x01;

    pub fn decode_body(input: &mut &[u8]) -> Result<Self> {
        Ok(Self {
            payload: read_i64_be(input)?,
        })
    }
}

impl<'a> PacketDecode<'a> for StatusPingC2s {
    const ID: i32 = StatusPingC2s::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        StatusPingC2s::decode_body(input)
    }
}

impl PacketEncode for StatusPingC2s {
    const ID: i32 = StatusPingC2s::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        write_i64_be(out, self.payload);
        Ok(())
    }
}

impl<'a> StatusResponseS2c<'a> {
    pub const ID: i32 = 0x00;

    pub fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Ok(Self {
            json: read_string_bounded(input, 32_767)?,
        })
    }
}

impl<'a> PacketDecode<'a> for StatusResponseS2c<'a> {
    const ID: i32 = StatusResponseS2c::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        StatusResponseS2c::decode_body(input)
    }
}

impl<'a> PacketEncode for StatusResponseS2c<'a> {
    const ID: i32 = StatusResponseS2c::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        write_string_bounded(out, self.json, 32_767)
    }
}

impl StatusPongS2c {
    pub const ID: i32 = 0x01;

    pub fn decode_body(input: &mut &[u8]) -> Result<Self> {
        Ok(Self {
            payload: read_i64_be(input)?,
        })
    }
}

impl<'a> PacketDecode<'a> for StatusPongS2c {
    const ID: i32 = StatusPongS2c::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        StatusPongS2c::decode_body(input)
    }
}

impl PacketEncode for StatusPongS2c {
    const ID: i32 = StatusPongS2c::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        write_i64_be(out, self.payload);
        Ok(())
    }
}

impl<'a> LoginDisconnectS2c<'a> {
    pub const ID: i32 = 0x00;

    pub fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Ok(Self {
            reason: read_string_bounded(input, 32_767)?,
        })
    }
}

impl<'a> PacketDecode<'a> for LoginDisconnectS2c<'a> {
    const ID: i32 = LoginDisconnectS2c::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        LoginDisconnectS2c::decode_body(input)
    }
}

impl<'a> PacketEncode for LoginDisconnectS2c<'a> {
    const ID: i32 = LoginDisconnectS2c::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        write_string_bounded(out, self.reason, 32_767)
    }
}

impl<'a> LoginStartC2s<'a> {
    pub const ID: i32 = 0x00;

    pub fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        let username = read_string_bounded(input, 16)?;
        let has_uuid = read_bool(input)?;
        let profile_id = if has_uuid {
            Some(read_uuid(input)?)
        } else {
            None
        };

        Ok(Self {
            username,
            profile_id,
        })
    }
}

impl<'a> PacketDecode<'a> for LoginStartC2s<'a> {
    const ID: i32 = LoginStartC2s::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        LoginStartC2s::decode_body(input)
    }
}

impl<'a> PacketEncode for LoginStartC2s<'a> {
    const ID: i32 = LoginStartC2s::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        write_string_bounded(out, self.username, 16)?;
        match &self.profile_id {
            Some(uuid) => {
                write_bool(out, true);
                write_uuid(out, uuid);
            }
            None => write_bool(out, false),
        }
        Ok(())
    }
}
