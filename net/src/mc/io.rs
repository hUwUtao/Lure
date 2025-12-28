use super::{
    Uuid,
    error::{ProtoError, Result},
    varint::read_varint,
};

#[inline]
pub(crate) fn take<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    if input.len() < len {
        return Err(ProtoError::UnexpectedEof);
    }

    let (head, tail) = input.split_at(len);
    *input = tail;
    Ok(head)
}

#[inline]
pub(crate) fn read_u8(input: &mut &[u8]) -> Result<u8> {
    Ok(take(input, 1)?[0])
}

#[inline]
pub(crate) fn read_bool(input: &mut &[u8]) -> Result<bool> {
    let value = read_u8(input)?;
    match value {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(ProtoError::InvalidBool(other)),
    }
}

#[inline]
pub(crate) fn write_bool(out: &mut Vec<u8>, value: bool) {
    out.push(value as u8);
}

#[inline]
pub(crate) fn read_u16_be(input: &mut &[u8]) -> Result<u16> {
    let bytes: [u8; 2] = take(input, 2)?.try_into().unwrap();
    Ok(u16::from_be_bytes(bytes))
}

#[inline]
pub(crate) fn write_u16_be(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[inline]
pub(crate) fn read_i64_be(input: &mut &[u8]) -> Result<i64> {
    let bytes: [u8; 8] = take(input, 8)?.try_into().unwrap();
    Ok(i64::from_be_bytes(bytes))
}

#[inline]
pub(crate) fn write_i64_be(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[inline]
pub(crate) fn read_u64_be(input: &mut &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = take(input, 8)?.try_into().unwrap();
    Ok(u64::from_be_bytes(bytes))
}

#[inline]
pub(crate) fn write_u64_be(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[inline]
pub(crate) fn read_uuid(input: &mut &[u8]) -> Result<Uuid> {
    let msb = read_u64_be(input)?;
    let lsb = read_u64_be(input)?;
    Ok(Uuid::from_u64s(msb, lsb))
}

#[inline]
pub(crate) fn write_uuid(out: &mut Vec<u8>, value: &Uuid) {
    let (msb, lsb) = value.as_u64s();
    write_u64_be(out, msb);
    write_u64_be(out, lsb);
}

pub(crate) fn read_string_bounded<'a>(input: &mut &'a [u8], max_chars: usize) -> Result<&'a str> {
    let byte_len = read_varint(input)?;
    if byte_len < 0 {
        return Err(ProtoError::NegativeLength(byte_len));
    }

    let byte_len = byte_len as usize;
    let max_bytes = max_chars.saturating_mul(4);
    if byte_len > max_bytes {
        return Err(ProtoError::LengthTooLarge {
            max: max_bytes,
            actual: byte_len,
        });
    }

    let bytes = take(input, byte_len)?;
    let s = std::str::from_utf8(bytes).map_err(|_| ProtoError::InvalidUtf8)?;

    let char_count = s.encode_utf16().count();
    if char_count > max_chars {
        return Err(ProtoError::StringTooLong {
            max: max_chars,
            actual: char_count,
        });
    }

    Ok(s)
}

pub(crate) fn write_string_bounded(out: &mut Vec<u8>, value: &str, max_chars: usize) -> Result<()> {
    let char_count = value.encode_utf16().count();
    if char_count > max_chars {
        return Err(ProtoError::StringTooLong {
            max: max_chars,
            actual: char_count,
        });
    }

    let len = value.len();
    if len > i32::MAX as usize {
        return Err(ProtoError::LengthTooLarge {
            max: i32::MAX as usize,
            actual: len,
        });
    }

    super::varint::write_varint(out, len as i32);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
