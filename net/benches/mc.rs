use criterion::{Criterion, black_box, criterion_group, criterion_main};
use net::{
    HandshakeC2s, HandshakeNextState, LoginDisconnectS2c, LoginStartC2s, PacketDecoder,
    PacketEncode, PacketFrame, PacketState, ProtoError, StatusPingC2s, StatusPongS2c,
    StatusRequestC2s, StatusResponseS2c, Uuid, encode_packet, mc::Result as McResult,
};

const L7_TRUNCATE_LEN: usize = 16;
const PROTOCOL_VERSION: i32 = 763;

const STATUS_JSON: &str = "{\"version\":{\"name\":\"1.20.4\",\"protocol\":763},\"players\":{\"max\":10,\"online\":0},\"description\":{\"text\":\"Lure\"}}";
const LOGIN_REASON: &str = "{\"text\":\"Bye\"}";
const USERNAME: &str = "player";

enum PacketRef<'a> {
    Handshake(HandshakeC2s<'a>),
    StatusRequest(StatusRequestC2s),
    StatusPing(StatusPingC2s),
    StatusResponse(StatusResponseS2c<'a>),
    StatusPong(StatusPongS2c),
    LoginDisconnect(LoginDisconnectS2c<'a>),
    LoginStart(LoginStartC2s<'a>),
}

impl<'a> PacketRef<'a> {
    fn encode_into(&self, out: &mut Vec<u8>) -> McResult<()> {
        match self {
            PacketRef::Handshake(packet) => encode_packet(out, packet),
            PacketRef::StatusRequest(packet) => encode_packet(out, packet),
            PacketRef::StatusPing(packet) => encode_packet(out, packet),
            PacketRef::StatusResponse(packet) => encode_packet(out, packet),
            PacketRef::StatusPong(packet) => encode_packet(out, packet),
            PacketRef::LoginDisconnect(packet) => encode_packet(out, packet),
            PacketRef::LoginStart(packet) => encode_login_start(out, packet),
        }
    }
}

struct PacketEntry<'a> {
    packet: PacketRef<'a>,
    decode: fn(&PacketFrame) -> McResult<()>,
}

struct EncodedPacket {
    bytes: Vec<u8>,
    decode: fn(&PacketFrame) -> McResult<()>,
}

struct VersionedLoginStart<'a> {
    packet: &'a LoginStartC2s<'a>,
    protocol_version: i32,
}

impl<'a> PacketEncode for VersionedLoginStart<'a> {
    const ID: i32 = LoginStartC2s::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> McResult<()> {
        self.packet
            .encode_body_with_version(out, self.protocol_version)
    }
}

fn encode_login_start(out: &mut Vec<u8>, packet: &LoginStartC2s<'_>) -> McResult<()> {
    let versioned = VersionedLoginStart {
        packet,
        protocol_version: PROTOCOL_VERSION,
    };
    encode_packet(out, &versioned)
}

fn decode_handshake(frame: &PacketFrame) -> McResult<()> {
    let decoded = frame.decode_serverbound(PacketState::Handshaking, PROTOCOL_VERSION)?;
    black_box(decoded);
    Ok(())
}

fn decode_status_request(frame: &PacketFrame) -> McResult<()> {
    let decoded = frame.decode_serverbound(PacketState::Status, PROTOCOL_VERSION)?;
    black_box(decoded);
    Ok(())
}

fn decode_status_ping(frame: &PacketFrame) -> McResult<()> {
    let decoded = frame.decode_serverbound(PacketState::Status, PROTOCOL_VERSION)?;
    black_box(decoded);
    Ok(())
}

fn decode_login_start(frame: &PacketFrame) -> McResult<()> {
    let decoded = frame.decode_serverbound(PacketState::Login, PROTOCOL_VERSION)?;
    black_box(decoded);
    Ok(())
}

fn decode_status_response(frame: &PacketFrame) -> McResult<()> {
    let mut body = frame.body.as_slice();
    let decoded = StatusResponseS2c::decode_body(&mut body)?;
    if !body.is_empty() {
        return Err(ProtoError::TrailingBytes(body.len()));
    }
    black_box(decoded);
    Ok(())
}

fn decode_status_pong(frame: &PacketFrame) -> McResult<()> {
    let mut body = frame.body.as_slice();
    let decoded = StatusPongS2c::decode_body(&mut body)?;
    if !body.is_empty() {
        return Err(ProtoError::TrailingBytes(body.len()));
    }
    black_box(decoded);
    Ok(())
}

fn decode_login_disconnect(frame: &PacketFrame) -> McResult<()> {
    let mut body = frame.body.as_slice();
    let decoded = LoginDisconnectS2c::decode_body(&mut body)?;
    if !body.is_empty() {
        return Err(ProtoError::TrailingBytes(body.len()));
    }
    black_box(decoded);
    Ok(())
}

fn packet_entries() -> Vec<PacketEntry<'static>> {
    vec![
        PacketEntry {
            packet: PacketRef::Handshake(HandshakeC2s {
                protocol_version: PROTOCOL_VERSION,
                server_address: "localhost",
                server_port: 25565,
                next_state: HandshakeNextState::Login,
            }),
            decode: decode_handshake,
        },
        PacketEntry {
            packet: PacketRef::StatusRequest(StatusRequestC2s),
            decode: decode_status_request,
        },
        PacketEntry {
            packet: PacketRef::StatusPing(StatusPingC2s { payload: 1_234_567 }),
            decode: decode_status_ping,
        },
        PacketEntry {
            packet: PacketRef::StatusResponse(StatusResponseS2c { json: STATUS_JSON }),
            decode: decode_status_response,
        },
        PacketEntry {
            packet: PacketRef::StatusPong(StatusPongS2c { payload: 1_234_567 }),
            decode: decode_status_pong,
        },
        PacketEntry {
            packet: PacketRef::LoginDisconnect(LoginDisconnectS2c {
                reason: LOGIN_REASON,
            }),
            decode: decode_login_disconnect,
        },
        PacketEntry {
            packet: PacketRef::LoginStart(LoginStartC2s {
                username: USERNAME,
                profile_id: Some(Uuid::from_u64s(
                    0x0102_0304_0506_0708,
                    0x090a_0b0c_0d0e_0f10,
                )),
                sig_data: None,
            }),
            decode: decode_login_start,
        },
    ]
}

fn upper_pair_entries() -> Vec<PacketEntry<'static>> {
    vec![
        PacketEntry {
            packet: PacketRef::LoginStart(LoginStartC2s {
                username: USERNAME,
                profile_id: Some(Uuid::from_u64s(
                    0x0102_0304_0506_0708,
                    0x090a_0b0c_0d0e_0f10,
                )),
                sig_data: None,
            }),
            decode: decode_login_start,
        },
        PacketEntry {
            packet: PacketRef::LoginDisconnect(LoginDisconnectS2c {
                reason: LOGIN_REASON,
            }),
            decode: decode_login_disconnect,
        },
    ]
}

fn bench_encode_round_robin(c: &mut Criterion) {
    let packets = packet_entries();
    let mut idx = 0usize;
    let mut out = Vec::with_capacity(256);

    c.bench_function("encode_round_robin", |b| {
        b.iter(|| {
            let entry = &packets[idx];
            idx = (idx + 1) % packets.len();
            out.clear();
            entry.packet.encode_into(&mut out).unwrap();
            black_box(&out);
        })
    });
}

fn bench_decode_round_robin(c: &mut Criterion) {
    let packets = packet_entries();
    let encoded: Vec<EncodedPacket> = packets
        .into_iter()
        .map(|entry| {
            let mut bytes = Vec::new();
            entry.packet.encode_into(&mut bytes).unwrap();
            EncodedPacket {
                bytes,
                decode: entry.decode,
            }
        })
        .collect();

    let mut idx = 0usize;
    let mut decoder = PacketDecoder::new();

    c.bench_function("decode_round_robin", |b| {
        b.iter(|| {
            let entry = &encoded[idx];
            idx = (idx + 1) % encoded.len();
            decoder.queue_slice(&entry.bytes);
            let frame = decoder.try_next_packet().unwrap().unwrap();
            (entry.decode)(&frame).unwrap();
            black_box(frame);
        })
    });
}

fn bench_l7_stress_error(c: &mut Criterion) {
    let packets = upper_pair_entries();
    let mut idx = 0usize;
    let mut out = Vec::with_capacity(256);
    let mut decoder = PacketDecoder::new();

    c.bench_function("l7_stress_error", |b| {
        b.iter(|| {
            let entry = &packets[idx];
            idx = (idx + 1) % packets.len();
            out.clear();
            entry.packet.encode_into(&mut out).unwrap();
            decoder.queue_slice(&out);
            let frame = decoder.try_next_packet().unwrap().unwrap();
            let full_len = frame.body.len();
            let trunc_len = if full_len == 0 {
                0
            } else {
                let target = full_len.saturating_sub(1);
                let truncated = L7_TRUNCATE_LEN.min(target);
                if truncated == 0 { 1 } else { truncated }
            };
            let truncated = PacketFrame {
                id: frame.id,
                body: frame.body[..trunc_len].to_vec(),
            };
            let errored = (entry.decode)(&truncated).is_err();
            black_box(errored);
        })
    });
}

criterion_group!(
    benches,
    bench_encode_round_robin,
    bench_decode_round_robin,
    bench_l7_stress_error
);
criterion_main!(benches);
