use super::{
    packets::{HandshakeC2s, LoginDisconnectS2c, LoginStartC2s, ServerboundPacket, StatusPingC2s},
    state::{HandshakeNextState, PacketState},
    types::{PacketDecoder, PacketEncode, PacketEncoder, Uuid},
    varint::{read_varint, write_varint},
};

const PROTOCOL_VERSION: i32 = 763;

struct VersionedLoginStart<'a> {
    packet: &'a LoginStartC2s<'a>,
    protocol_version: i32,
}

impl<'a> PacketEncode for VersionedLoginStart<'a> {
    const ID: i32 = LoginStartC2s::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> super::error::Result<()> {
        self.packet
            .encode_body_with_version(out, self.protocol_version)
    }
}

#[test]
fn varint_roundtrip() {
    let values = [0, 1, 2, 127, 128, 255, 2_147_483_647, -1, -2_147_483_648];
    for value in values {
        let mut buf = Vec::new();
        write_varint(&mut buf, value);
        let mut slice = buf.as_slice();
        let decoded = read_varint(&mut slice).unwrap();
        assert_eq!(decoded, value);
        assert!(slice.is_empty());
    }
}

#[test]
fn handshake_roundtrip() {
    let packet = HandshakeC2s {
        protocol_version: PROTOCOL_VERSION,
        server_address: "localhost",
        server_port: 25565,
        next_state: HandshakeNextState::Login,
    };

    let mut enc = PacketEncoder::new();
    enc.write_packet(&packet).unwrap();
    let bytes = enc.take();

    let mut dec = PacketDecoder::new();
    dec.queue_slice(&bytes);
    let frame = dec.try_next_packet().unwrap().unwrap();
    let decoded = frame
        .decode_serverbound(PacketState::Handshaking, PROTOCOL_VERSION)
        .unwrap();

    match decoded {
        ServerboundPacket::Handshake(actual) => assert_eq!(actual, packet),
        _ => panic!("unexpected packet"),
    }
}

#[test]
fn login_start_roundtrip() {
    let packet = LoginStartC2s {
        username: "player",
        profile_id: Some(Uuid::from_u64s(
            0x0102_0304_0506_0708,
            0x090a_0b0c_0d0e_0f10,
        )),
    };

    let mut enc = PacketEncoder::new();
    let versioned = VersionedLoginStart {
        packet: &packet,
        protocol_version: PROTOCOL_VERSION,
    };
    enc.write_packet(&versioned).unwrap();
    let bytes = enc.take();

    let mut dec = PacketDecoder::new();
    dec.queue_slice(&bytes);
    let frame = dec.try_next_packet().unwrap().unwrap();
    let decoded = frame
        .decode_serverbound(PacketState::Login, PROTOCOL_VERSION)
        .unwrap();

    match decoded {
        ServerboundPacket::LoginStart(actual) => assert_eq!(actual, packet),
        _ => panic!("unexpected packet"),
    }
}

#[test]
fn status_ping_roundtrip() {
    let packet = StatusPingC2s { payload: 1_234_567 };

    let mut enc = PacketEncoder::new();
    enc.write_packet(&packet).unwrap();
    let bytes = enc.take();

    let mut dec = PacketDecoder::new();
    dec.queue_slice(&bytes);
    let frame = dec.try_next_packet().unwrap().unwrap();
    let decoded = frame
        .decode_serverbound(PacketState::Status, PROTOCOL_VERSION)
        .unwrap();

    match decoded {
        ServerboundPacket::StatusPing(actual) => assert_eq!(actual, packet),
        _ => panic!("unexpected packet"),
    }
}

#[test]
fn login_disconnect_roundtrip() {
    let packet = LoginDisconnectS2c {
        reason: "{\"text\":\"Bye\"}",
    };

    let mut enc = PacketEncoder::new();
    enc.write_packet(&packet).unwrap();
    let bytes = enc.take();

    let mut dec = PacketDecoder::new();
    dec.queue_slice(&bytes);
    let frame = dec.try_next_packet().unwrap().unwrap();
    assert_eq!(frame.id, LoginDisconnectS2c::ID);

    let mut body = frame.body.as_slice();
    let decoded = LoginDisconnectS2c::decode_body(&mut body).unwrap();
    assert_eq!(decoded, packet);
    assert!(body.is_empty());
}
