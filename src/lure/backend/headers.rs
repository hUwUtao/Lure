use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::BytesMut;
use ed25519_dalek::{Signature, Signer, SigningKey};
use log::warn;
use net::{AddressInfo, Command, Family, Header, Protocol, Tlv};

use crate::config::LureConfig;

const SIGNATURE_VERSION: u8 = 1;
const SIGNATURE_ALGO_ED25519: u8 = 1;
const SIGNATURE_CONTEXT: &[u8] = b"LUREPROXY";

pub(crate) fn create_proxy_protocol_header(
    socket: SocketAddr,
    config: &LureConfig,
) -> anyhow::Result<BytesMut> {
    let (family, address) = match socket {
        SocketAddr::V4(addr) => (
            Family::Inet,
            AddressInfo::Ipv4(addr, SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        ),
        SocketAddr::V6(addr) => (
            Family::Inet6,
            AddressInfo::Ipv6(addr, SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
        ),
    };

    let proxy_header = Header {
        command: Command::Proxy,
        family,
        protocol: Protocol::Stream,
        address,
        tlvs: create_header(config, socket),
    };
    Ok(BytesMut::from(proxy_header.serialize().as_slice()))
}

fn create_header(cfg: &LureConfig, client_addr: SocketAddr) -> Vec<Tlv> {
    let mut headers = Vec::<Tlv>::new();

    headers.push(Tlv::Authority(Box::from(cfg.inst.as_str())));

    let Some(key) = cfg
        .proxy_signing_key
        .as_ref()
        .map(|key| key.as_bytes())
        .filter(|value| !value.is_empty())
    else {
        return headers;
    };

    let seed = match key.len() {
        32 => &key[..32],
        64 => &key[..32],
        other => {
            warn!("proxy_signing_key must be 32 or 64 bytes, got {other}");
            return headers;
        }
    };
    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(seed);
    let signing_key = SigningKey::from_bytes(&seed_bytes);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let signature = sign_proxy_header(&signing_key, cfg.inst.as_str(), client_addr, timestamp);

    let mut payload = Vec::with_capacity(2 + 8 + signature.len());
    payload.push(SIGNATURE_VERSION);
    payload.push(SIGNATURE_ALGO_ED25519);
    payload.extend_from_slice(&timestamp.to_be_bytes());
    payload.extend_from_slice(&signature);
    headers.push(Tlv::UniqueId(payload.into_boxed_slice()));

    headers
}

fn sign_proxy_header(
    signing_key: &SigningKey,
    inst: &str,
    client_addr: SocketAddr,
    timestamp: u64,
) -> [u8; 64] {
    let mut msg =
        Vec::with_capacity(SIGNATURE_CONTEXT.len() + 1 + 1 + inst.len() + 1 + 8 + 1 + 16 + 2);
    msg.extend_from_slice(SIGNATURE_CONTEXT);
    msg.push(SIGNATURE_VERSION);
    msg.push(SIGNATURE_ALGO_ED25519);
    msg.extend_from_slice(inst.as_bytes());
    msg.push(0);
    msg.extend_from_slice(&timestamp.to_be_bytes());
    append_addr(&mut msg, client_addr);
    let signature: Signature = signing_key.sign(&msg);
    signature.to_bytes()
}

fn append_addr(out: &mut Vec<u8>, client_addr: SocketAddr) {
    match client_addr {
        SocketAddr::V4(addr) => {
            out.push(4);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            out.push(6);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
}
