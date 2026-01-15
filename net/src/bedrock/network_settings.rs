use super::error::{Error, Result};
use super::varint::{read_uvarint, write_uvarint};
use super::{NETWORK_SETTINGS_PACKET_ID, REQUEST_NETWORK_SETTINGS_PACKET_ID};

pub const COMPRESSION_ALGORITHM_ZLIB: u16 = 0;
pub const COMPRESSION_ALGORITHM_SNAPPY: u16 = 1;
pub const COMPRESSION_ALGORITHM_NONE: u16 = 255;

#[derive(Debug, Clone, Copy)]
pub struct NetworkSettings {
    pub compression_threshold: u16,
    pub compression_algorithm: u16,
    pub enable_client_throttling: bool,
    pub client_throttle_threshold: u8,
    pub client_throttle_scalar: f32,
}

pub fn decode_request_network_settings(packet: &[u8]) -> Result<u32> {
    let mut input = packet;
    let packet_id = read_uvarint(&mut input)?;
    if packet_id != REQUEST_NETWORK_SETTINGS_PACKET_ID {
        return Err(Error::InvalidPacketId {
            expected: REQUEST_NETWORK_SETTINGS_PACKET_ID,
            actual: packet_id,
        });
    }

    read_be_u32(&mut input)
}

pub fn encode_network_settings(settings: &NetworkSettings) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    write_uvarint(&mut out, NETWORK_SETTINGS_PACKET_ID);
    out.extend_from_slice(&settings.compression_threshold.to_le_bytes());
    out.extend_from_slice(&settings.compression_algorithm.to_le_bytes());
    out.push(if settings.enable_client_throttling { 1 } else { 0 });
    out.push(settings.client_throttle_threshold);
    out.extend_from_slice(&settings.client_throttle_scalar.to_le_bytes());
    out
}

pub fn decode_network_settings(packet: &[u8]) -> Result<NetworkSettings> {
    let mut input = packet;
    let packet_id = read_uvarint(&mut input)?;
    if packet_id != NETWORK_SETTINGS_PACKET_ID {
        return Err(Error::InvalidPacketId {
            expected: NETWORK_SETTINGS_PACKET_ID,
            actual: packet_id,
        });
    }

    let compression_threshold = read_le_u16(&mut input)?;
    let compression_algorithm = read_le_u16(&mut input)?;
    let enable_client_throttling = read_bool_u8(&mut input)?;
    let client_throttle_threshold = read_u8(&mut input)?;
    let client_throttle_scalar = read_f32(&mut input)?;

    Ok(NetworkSettings {
        compression_threshold,
        compression_algorithm,
        enable_client_throttling,
        client_throttle_threshold,
        client_throttle_scalar,
    })
}

fn read_be_u32(input: &mut &[u8]) -> Result<u32> {
    if input.len() < 4 {
        return Err(Error::UnexpectedEof);
    }
    let (value, rest) = input.split_at(4);
    *input = rest;
    Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_le_u16(input: &mut &[u8]) -> Result<u16> {
    if input.len() < 2 {
        return Err(Error::UnexpectedEof);
    }
    let (value, rest) = input.split_at(2);
    *input = rest;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u8(input: &mut &[u8]) -> Result<u8> {
    if input.is_empty() {
        return Err(Error::UnexpectedEof);
    }
    let value = input[0];
    *input = &input[1..];
    Ok(value)
}

fn read_bool_u8(input: &mut &[u8]) -> Result<bool> {
    Ok(read_u8(input)? != 0)
}

fn read_f32(input: &mut &[u8]) -> Result<f32> {
    if input.len() < 4 {
        return Err(Error::UnexpectedEof);
    }
    let (value, rest) = input.split_at(4);
    *input = rest;
    Ok(f32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}
