/// Extract raw JSON string bytes from a framed Status Response packet
///
/// The Status Response packet format is:
/// - Packet ID (0x00, varint)
/// - JSON string (length-prefixed UTF-8 string)
///
/// This function returns the raw bytes of the JSON string (without the length prefix).
pub fn extract_status_json(packet: &[u8]) -> Option<&[u8]> {
    // Skip the packet ID (0x00, single byte varint)
    if packet.is_empty() {
        return None;
    }
    let mut pos = 1;

    // Read the string length (varint-encoded)
    let mut len: usize = 0;
    let mut shift = 0;
    loop {
        if pos >= packet.len() {
            return None;
        }
        let byte = packet[pos];
        pos += 1;
        len |= ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 32 {
            return None; // Varint too long
        }
    }

    // Extract the JSON string bytes
    if pos + len > packet.len() {
        return None;
    }
    Some(&packet[pos..pos + len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_status_json_simple() {
        // Packet ID: 0x00
        // String length: 2 (single byte varint)
        // String: "ab"
        let packet = [0x00, 0x02, b'a', b'b'];
        assert_eq!(extract_status_json(&packet), Some(&b"ab"[..]));
    }

    #[test]
    fn test_extract_status_json_empty() {
        let packet = [0x00, 0x00];
        assert_eq!(extract_status_json(&packet), Some(&b""[..]));
    }

    #[test]
    fn test_extract_status_json_multibye_length() {
        // Packet ID: 0x00
        // String length: 128 (0x80, 0x01 = 0x80 | (0x01 << 7))
        let mut packet = vec![0x00, 0x80, 0x01];
        packet.extend(vec![b'a'; 128]);
        assert_eq!(extract_status_json(&packet), Some(&packet[3..]));
    }

    #[test]
    fn test_extract_status_json_truncated() {
        let packet = [0x00, 0x05, b'a', b'b'];
        assert_eq!(extract_status_json(&packet), None);
    }

    #[test]
    fn test_extract_status_json_empty_packet() {
        assert_eq!(extract_status_json(&[]), None);
    }
}
