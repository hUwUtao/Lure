use super::{LOGIN_PACKET_ID, error::{Error, Result}, jwt::extract_server_address, varint::read_uvarint};

#[derive(Debug, Clone)]
pub struct LoginPacket {
    pub protocol: u32,
    pub auth_info_json: Vec<u8>,
    pub client_data_jwt: Vec<u8>,
}

impl LoginPacket {
    pub fn client_data_jwt_str(&self) -> Result<&str> {
        Ok(std::str::from_utf8(&self.client_data_jwt)?)
    }

    pub fn server_address(&self) -> Result<Option<String>> {
        let jwt = self.client_data_jwt_str()?;
        extract_server_address(jwt)
    }
}

pub fn decode_login_packet(packet: &[u8]) -> Result<LoginPacket> {
    let mut input = packet;
    let packet_id = read_uvarint(&mut input)?;
    if packet_id != LOGIN_PACKET_ID {
        return Err(Error::InvalidPacketId {
            expected: LOGIN_PACKET_ID,
            actual: packet_id,
        });
    }
    decode_login_payload(input)
}

pub fn decode_login_payload(payload: &[u8]) -> Result<LoginPacket> {
    let mut input = payload;
    let protocol = read_be_u32(&mut input)?;
    let conn_len = read_uvarint(&mut input)? as usize;
    if input.len() < conn_len {
        return Err(Error::UnexpectedEof);
    }
    let (conn_req, _) = input.split_at(conn_len);
    let mut conn = conn_req;

    let auth_len = read_le_u32(&mut conn)? as usize;
    if conn.len() < auth_len {
        return Err(Error::UnexpectedEof);
    }
    let (auth_info_json, rest) = conn.split_at(auth_len);
    conn = rest;

    let jwt_len = read_le_u32(&mut conn)? as usize;
    if conn.len() < jwt_len {
        return Err(Error::UnexpectedEof);
    }
    let (client_data_jwt, _) = conn.split_at(jwt_len);

    Ok(LoginPacket {
        protocol,
        auth_info_json: auth_info_json.to_vec(),
        client_data_jwt: client_data_jwt.to_vec(),
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

fn read_le_u32(input: &mut &[u8]) -> Result<u32> {
    if input.len() < 4 {
        return Err(Error::UnexpectedEof);
    }
    let (value, rest) = input.split_at(4);
    *input = rest;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    use crate::bedrock::varint::write_uvarint;

    fn build_login_packet(jwt: &str, auth_info: &str) -> Vec<u8> {
        let mut conn = Vec::new();
        conn.extend_from_slice(&(auth_info.len() as u32).to_le_bytes());
        conn.extend_from_slice(auth_info.as_bytes());
        conn.extend_from_slice(&(jwt.len() as u32).to_le_bytes());
        conn.extend_from_slice(jwt.as_bytes());

        let mut out = Vec::new();
        write_uvarint(&mut out, LOGIN_PACKET_ID);
        out.extend_from_slice(&1u32.to_be_bytes());
        write_uvarint(&mut out, conn.len() as u32);
        out.extend_from_slice(&conn);
        out
    }

    #[test]
    fn login_extracts_server_address() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"ServerAddress":"play.example.com:19132"}"#);
        let jwt = format!("{header}.{payload}.");
        let packet = build_login_packet(&jwt, "{}");

        let login = decode_login_packet(&packet).expect("decode login");
        let address = login.server_address().expect("jwt parse");
        assert_eq!(address.as_deref(), Some("play.example.com:19132"));
    }
}
