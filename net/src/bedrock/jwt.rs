use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use super::error::{Error, Result};

pub fn decode_payload(jwt: &str) -> Result<serde_json::Value> {
    let mut parts = jwt.split('.');
    let _header = parts.next();
    let Some(payload_b64) = parts.next() else {
        return Err(Error::InvalidJwt);
    };

    let payload = URL_SAFE_NO_PAD.decode(payload_b64)?;
    Ok(serde_json::from_slice(&payload)?)
}

pub fn extract_server_address(jwt: &str) -> Result<Option<String>> {
    let payload = decode_payload(jwt)?;
    let Some(value) = payload.get("ServerAddress") else {
        return Ok(None);
    };

    match value.as_str() {
        Some(value) => Ok(Some(value.to_string())),
        None => Err(Error::InvalidJwt),
    }
}
