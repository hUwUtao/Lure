use std::io::Read;

use flate2::read::ZlibDecoder;
use snap::raw::{Decoder as SnappyDecoder, Encoder as SnappyEncoder};

use super::{
    PACKET_BATCH_ID,
    error::{Error, Result},
    varint::{read_uvarint, write_uvarint},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Zlib,
    Snappy,
}

pub fn decode_packet_batch(packet: &[u8], compression: Compression) -> Result<Vec<Vec<u8>>> {
    let mut input = packet;
    let packet_id = read_uvarint(&mut input)?;
    if packet_id != PACKET_BATCH_ID {
        return Err(Error::InvalidPacketId {
            expected: PACKET_BATCH_ID,
            actual: packet_id,
        });
    }
    decode_batch_payload(input, compression)
}

pub fn decode_batch_payload(payload: &[u8], compression: Compression) -> Result<Vec<Vec<u8>>> {
    let payload = match compression {
        Compression::None => payload.to_vec(),
        Compression::Zlib => {
            let mut decoder = ZlibDecoder::new(payload);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out)?;
            out
        }
        Compression::Snappy => {
            let mut decoder = SnappyDecoder::new();
            decoder.decompress_vec(payload)?
        }
    };

    let mut input = payload.as_slice();
    let mut packets = Vec::new();
    while !input.is_empty() {
        let length = read_uvarint(&mut input)? as usize;
        if input.len() < length {
            return Err(Error::UnexpectedEof);
        }
        let (packet, rest) = input.split_at(length);
        packets.push(packet.to_vec());
        input = rest;
    }

    Ok(packets)
}

pub fn encode_packet_batch(packets: &[Vec<u8>], compression: Compression) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    for packet in packets {
        write_uvarint(&mut payload, packet.len() as u32);
        payload.extend_from_slice(packet);
    }

    let payload = match compression {
        Compression::None => payload,
        Compression::Zlib => {
            let mut encoder = flate2::write::ZlibEncoder::new(
                Vec::new(),
                flate2::Compression::default(),
            );
            std::io::Write::write_all(&mut encoder, &payload)?;
            encoder.finish()?
        }
        Compression::Snappy => {
            let mut encoder = SnappyEncoder::new();
            encoder.compress_vec(&payload)?
        }
    };

    let mut out = Vec::with_capacity(payload.len() + 5);
    write_uvarint(&mut out, PACKET_BATCH_ID);
    out.extend_from_slice(&payload);
    Ok(out)
}
