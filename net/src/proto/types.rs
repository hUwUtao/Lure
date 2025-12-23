use super::{
    error::{ProtoError, Result, debug_log_error},
    varint::{read_varint, read_varint_partial, varint_len, write_varint},
};

/// Maximum packet length in bytes (protocol limit).
pub const MAX_PACKET_SIZE: usize = 2_097_152;

/// UUID stored as 16 raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uuid([u8; 16]);

impl Uuid {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn from_u64s(msb: u64, lsb: u64) -> Self {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&msb.to_be_bytes());
        bytes[8..].copy_from_slice(&lsb.to_be_bytes());
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn as_u64s(&self) -> (u64, u64) {
        let msb = u64::from_be_bytes(self.0[..8].try_into().unwrap());
        let lsb = u64::from_be_bytes(self.0[8..].try_into().unwrap());
        (msb, lsb)
    }
}

/// Clientbound or serverbound packet body encoding.
pub trait PacketEncode {
    const ID: i32;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()>;
}

/// Clientbound or serverbound packet body decoding.
pub trait PacketDecode<'a>: Sized {
    const ID: i32;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self>;
}

/// Decoded packet frame with the raw body (without ID).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketFrame {
    pub id: i32,
    pub body: Vec<u8>,
}

/// Packet decoder for length-prefixed frames.
pub struct PacketDecoder {
    buf: Vec<u8>,
    pos: usize,
}

/// Packet encoder for length-prefixed frames.
pub struct PacketEncoder {
    buf: Vec<u8>,
    scratch: Vec<u8>,
}

impl PacketDecoder {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            pos: 0,
        }
    }

    pub fn queue_slice(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub fn take_pending_bytes(&mut self) -> Vec<u8> {
        if self.buf.is_empty() {
            return Vec::new();
        }

        if self.pos == 0 {
            return std::mem::take(&mut self.buf);
        }

        if self.pos >= self.buf.len() {
            self.buf.clear();
            self.pos = 0;
            return Vec::new();
        }

        let pending = self.buf.split_off(self.pos);
        self.buf.clear();
        self.pos = 0;
        pending
    }

    pub fn try_next_packet(&mut self) -> Result<Option<PacketFrame>> {
        let data = &self.buf[self.pos..];
        let (packet_len, len_len) = match read_varint_partial(data) {
            Ok(Some(value)) => value,
            Ok(None) => return Ok(None),
            Err(err) => {
                debug_log_error("packet length varint decode failed", &err);
                return Err(err);
            }
        };

        if packet_len < 0 {
            let err = ProtoError::NegativeLength(packet_len);
            debug_log_error("negative packet length", &err);
            return Err(err);
        }

        let packet_len = packet_len as usize;
        if packet_len > MAX_PACKET_SIZE {
            let err = ProtoError::PacketTooLarge { len: packet_len };
            debug_log_error("packet too large", &err);
            return Err(err);
        }

        let total_len = len_len + packet_len;
        if data.len() < total_len {
            return Ok(None);
        }

        let packet = &data[len_len..total_len];
        let mut body = packet;
        let id = match read_varint(&mut body) {
            Ok(value) => value,
            Err(err) => {
                debug_log_error("packet id varint decode failed", &err);
                return Err(err);
            }
        };
        let body_vec = body.to_vec();

        self.pos += total_len;
        self.compact_if_needed();

        Ok(Some(PacketFrame { id, body: body_vec }))
    }

    fn compact_if_needed(&mut self) {
        if self.pos == 0 {
            return;
        }

        if self.pos >= self.buf.len() / 2 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }
}

impl PacketEncoder {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            scratch: Vec::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            scratch: Vec::new(),
        }
    }

    pub fn write_packet<P: PacketEncode>(&mut self, pkt: &P) -> Result<()> {
        self.scratch.clear();
        pkt.encode_body(&mut self.scratch)?;
        encode_raw_packet(&mut self.buf, P::ID, &self.scratch)
    }

    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    pub fn clear(&mut self) {
        self.buf.clear();
    }
}

pub fn encode_packet<P: PacketEncode>(out: &mut Vec<u8>, pkt: &P) -> Result<()> {
    let mut body = Vec::new();
    pkt.encode_body(&mut body)?;
    encode_raw_packet(out, P::ID, &body)
}

fn encode_raw_packet(out: &mut Vec<u8>, id: i32, body: &[u8]) -> Result<()> {
    let packet_len = varint_len(id) + body.len();
    if packet_len > MAX_PACKET_SIZE {
        return Err(ProtoError::PacketTooLarge { len: packet_len });
    }

    if packet_len > i32::MAX as usize {
        return Err(ProtoError::LengthTooLarge {
            max: i32::MAX as usize,
            actual: packet_len,
        });
    }

    write_varint(out, packet_len as i32);
    write_varint(out, id);
    out.extend_from_slice(body);
    Ok(())
}
