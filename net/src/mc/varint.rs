use super::error::{ProtoError, Result};

#[inline]
pub(crate) fn read_varint(input: &mut &[u8]) -> Result<i32> {
    let Some((value, len)) = read_varint_partial(input)? else {
        return Err(ProtoError::UnexpectedEof);
    };
    *input = &input[len..];
    Ok(value)
}

#[inline]
pub(crate) fn read_varint_partial(input: &[u8]) -> Result<Option<(i32, usize)>> {
    let mut value: u32 = 0;
    for i in 0..5 {
        if i >= input.len() {
            return Ok(None);
        }

        let byte = input[i];
        value |= ((byte & 0x7f) as u32) << (i * 7);
        if (byte & 0x80) == 0 {
            return Ok(Some((value as i32, i + 1)));
        }
    }

    Err(ProtoError::VarIntTooLarge)
}

#[inline]
pub(crate) fn write_varint(out: &mut Vec<u8>, value: i32) {
    let mut val = value as u32;
    loop {
        if (val & 0xffffff80) == 0 {
            out.push(val as u8);
            return;
        }
        out.push((val as u8 & 0x7f) | 0x80);
        val >>= 7;
    }
}

#[inline]
pub(crate) fn varint_len(value: i32) -> usize {
    let mut val = value as u32;
    let mut count = 1;
    while (val & 0xffffff80) != 0 {
        count += 1;
        val >>= 7;
    }
    count
}
