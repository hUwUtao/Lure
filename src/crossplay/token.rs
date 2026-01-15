use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::config::ProxySigningKey;

const TOKEN_PREFIX: &str = "lurex";
const TOKEN_VERSION: u8 = 1;
const TOKEN_CONTEXT: &[u8] = b"LUREXPLAY";

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("token is missing data")]
    MissingData,
    #[error("token is too large")]
    Oversized,
    #[error("token is invalid")]
    Invalid,
    #[error("token signature invalid")]
    BadSignature,
    #[error("token route is empty")]
    EmptyRoute,
    #[error("token route too long")]
    RouteTooLong,
}

#[derive(Debug, Clone)]
pub struct DecodedToken {
    pub route: Arc<str>,
    pub issued_at: u64,
}

#[derive(Debug, Clone)]
pub struct RoutingHost {
    pub routing_host: Arc<str>,
    pub stripped_address: Option<String>,
}

pub fn resolve_routing_host(
    server_address: &str,
    key: Option<&ProxySigningKey>,
) -> RoutingHost {
    let (base, suffix) = split_host_suffix(server_address);
    let Some((token_raw, remainder)) = extract_token_prefix(base) else {
        return RoutingHost {
            routing_host: Arc::from(base),
            stripped_address: None,
        };
    };

    let Some(key) = key.and_then(signing_key_from_config) else {
        return RoutingHost {
            routing_host: Arc::from(base),
            stripped_address: None,
        };
    };

    match decode_token(token_raw, &key) {
        Ok(decoded) => {
            let stripped = format!("{remainder}{suffix}");
            RoutingHost {
                routing_host: decoded.route,
                stripped_address: Some(stripped),
            }
        }
        Err(_) => RoutingHost {
            routing_host: Arc::from(base),
            stripped_address: None,
        },
    }
}

pub fn inject_token_hostname(
    server_address: &str,
    routing_host: &str,
    key: Option<&ProxySigningKey>,
) -> Result<String, TokenError> {
    let Some(key) = key.and_then(signing_key_from_config) else {
        return Err(TokenError::MissingData);
    };

    let (base, suffix) = split_host_suffix(server_address);
    if base.is_empty() {
        return Err(TokenError::EmptyRoute);
    }
    if base.starts_with(TOKEN_PREFIX) {
        return Ok(server_address.to_string());
    }

    let token = encode_token(routing_host, &key)?;
    Ok(format!("{TOKEN_PREFIX}.{token}.{base}{suffix}"))
}

fn split_host_suffix(server_address: &str) -> (&str, &str) {
    match server_address.find('\0') {
        Some(pos) => (&server_address[..pos], &server_address[pos..]),
        None => (server_address, ""),
    }
}

fn extract_token_prefix(base: &str) -> Option<(&str, &str)> {
    let mut parts = base.splitn(3, '.');
    let prefix = parts.next()?;
    if prefix != TOKEN_PREFIX {
        return None;
    }
    let token = parts.next()?;
    let remainder = parts.next().unwrap_or("");
    if remainder.is_empty() {
        return None;
    }
    Some((token, remainder))
}

fn encode_token(route: &str, key: &SigningKey) -> Result<String, TokenError> {
    if route.is_empty() {
        return Err(TokenError::EmptyRoute);
    }
    if route.len() > u8::MAX as usize {
        return Err(TokenError::RouteTooLong);
    }
    let issued_at = current_epoch();
    let payload = encode_payload(route, issued_at)?;
    let signature = sign_payload(key, &payload);
    let mut token = Vec::with_capacity(payload.len() + signature.len());
    token.extend_from_slice(&payload);
    token.extend_from_slice(&signature);
    Ok(URL_SAFE_NO_PAD.encode(token))
}

fn decode_token(token: &str, key: &SigningKey) -> Result<DecodedToken, TokenError> {
    let raw = URL_SAFE_NO_PAD.decode(token).map_err(|_| TokenError::Invalid)?;
    if raw.len() < 1 + 8 + 1 + 64 {
        return Err(TokenError::MissingData);
    }
    let payload_len = raw.len().saturating_sub(64);
    let (payload, sig_bytes) = raw.split_at(payload_len);
    let signature = Signature::from_slice(sig_bytes).map_err(|_| TokenError::Invalid)?;
    let verifying = VerifyingKey::from(key);
    verifying
        .verify(&signed_bytes(payload), &signature)
        .map_err(|_| TokenError::BadSignature)?;

    decode_payload(payload)
}

fn encode_payload(route: &str, issued_at: u64) -> Result<Vec<u8>, TokenError> {
    let route_bytes = route.as_bytes();
    if route_bytes.len() > u8::MAX as usize {
        return Err(TokenError::RouteTooLong);
    }
    let mut payload = Vec::with_capacity(1 + 8 + 1 + route_bytes.len());
    payload.push(TOKEN_VERSION);
    payload.extend_from_slice(&issued_at.to_be_bytes());
    payload.push(route_bytes.len() as u8);
    payload.extend_from_slice(route_bytes);
    Ok(payload)
}

fn decode_payload(payload: &[u8]) -> Result<DecodedToken, TokenError> {
    if payload.len() < 1 + 8 + 1 {
        return Err(TokenError::MissingData);
    }
    if payload[0] != TOKEN_VERSION {
        return Err(TokenError::Invalid);
    }
    let issued_at = u64::from_be_bytes([
        payload[1], payload[2], payload[3], payload[4], payload[5], payload[6], payload[7],
        payload[8],
    ]);
    let route_len = payload[9] as usize;
    if payload.len() < 10 + route_len {
        return Err(TokenError::MissingData);
    }
    let route = std::str::from_utf8(&payload[10..10 + route_len])
        .map_err(|_| TokenError::Invalid)?
        .trim();
    if route.is_empty() {
        return Err(TokenError::EmptyRoute);
    }
    Ok(DecodedToken {
        route: Arc::from(route),
        issued_at,
    })
}

fn sign_payload(key: &SigningKey, payload: &[u8]) -> [u8; 64] {
    let msg = signed_bytes(payload);
    let signature = key.sign(&msg);
    signature.to_bytes()
}

fn signed_bytes(payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(TOKEN_CONTEXT.len() + payload.len());
    msg.extend_from_slice(TOKEN_CONTEXT);
    msg.extend_from_slice(payload);
    msg
}

fn signing_key_from_config(key: &ProxySigningKey) -> Option<SigningKey> {
    let key_bytes = key.as_bytes();
    let seed = match key_bytes.len() {
        32 => &key_bytes[..32],
        64 => &key_bytes[..32],
        _ => return None,
    };
    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(seed);
    Some(SigningKey::from_bytes(&seed_bytes))
}

fn current_epoch() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
