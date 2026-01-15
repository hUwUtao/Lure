use super::error::{Error, Result};

pub fn read_uvarint(input: &mut &[u8]) -> Result<u32> {
    let mut result = 0u32;
    let mut shift = 0u32;
    for _ in 0..5 {
        let Some((&byte, rest)) = input.split_first() else {
            return Err(Error::UnexpectedEof);
        };
        *input = rest;
        result |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
    Err(Error::InvalidVarInt)
}

pub fn write_uvarint(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}
