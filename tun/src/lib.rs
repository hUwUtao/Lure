use std::net::{IpAddr, SocketAddr};

pub use net::sock;

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("buffer too short")]
    ShortBuffer,
    #[error("invalid magic")]
    InvalidMagic,
    #[error("unsupported version {0}")]
    UnsupportedVersion(u8),
    #[error("invalid intent {0}")]
    InvalidIntent(u8),
    #[error("invalid address family {0}")]
    InvalidAddrFamily(u8),
}

pub const MAGIC: [u8; 4] = *b"LTUN";
pub const VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Intent {
    Listen = 1,
    Connect = 2,
}

impl Intent {
    fn from_u8(value: u8) -> Result<Self, TunnelError> {
        match value {
            1 => Ok(Self::Listen),
            2 => Ok(Self::Connect),
            other => Err(TunnelError::InvalidIntent(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentHello {
    pub version: u8,
    pub intent: Intent,
    pub token: [u8; 32],
    pub session: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ServerMsgKind {
    SessionOffer = 1,
    TargetAddr = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerMsg {
    SessionOffer([u8; 32]),
    TargetAddr(SocketAddr),
}

pub async fn connect_agent(addr: SocketAddr) -> std::io::Result<sock::Connection> {
    sock::Connection::connect(addr).await
}

pub async fn listen_agent(addr: SocketAddr) -> std::io::Result<sock::Listener> {
    sock::Listener::bind(addr).await
}

pub fn decode_agent_hello(buf: &[u8]) -> Result<Option<(AgentHello, usize)>, TunnelError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    if buf[..4] != MAGIC {
        return Err(TunnelError::InvalidMagic);
    }
    if buf.len() < 4 + 1 + 1 + 32 {
        return Ok(None);
    }

    let version = buf[4];
    if version != VERSION {
        return Err(TunnelError::UnsupportedVersion(version));
    }

    let intent = Intent::from_u8(buf[5])?;
    let mut token = [0u8; 32];
    token.copy_from_slice(&buf[6..38]);

    let mut consumed = 38;
    let session = if intent == Intent::Connect {
        if buf.len() < consumed + 32 {
            return Ok(None);
        }
        let mut session = [0u8; 32];
        session.copy_from_slice(&buf[consumed..consumed + 32]);
        consumed += 32;
        Some(session)
    } else {
        None
    };

    Ok(Some((
        AgentHello {
            version,
            intent,
            token,
            session,
        },
        consumed,
    )))
}

pub fn encode_agent_hello(hello: &AgentHello, out: &mut Vec<u8>) -> Result<(), TunnelError> {
    // Validate intent/session invariant: only Connect may have a session, others must not
    match hello.intent {
        Intent::Connect => {
            // Connect must have a session
            if hello.session.is_none() {
                return Err(TunnelError::InvalidIntent(hello.intent as u8));
            }
        }
        Intent::Listen => {
            // Listen must not have a session
            if hello.session.is_some() {
                return Err(TunnelError::InvalidIntent(hello.intent as u8));
            }
        }
    }

    out.extend_from_slice(&MAGIC);
    out.push(hello.version);
    out.push(hello.intent as u8);
    out.extend_from_slice(&hello.token);
    if let Some(session) = hello.session {
        out.extend_from_slice(&session);
    }
    Ok(())
}

pub fn encode_server_msg(msg: &ServerMsg, out: &mut Vec<u8>) {
    match msg {
        ServerMsg::SessionOffer(token) => {
            out.push(ServerMsgKind::SessionOffer as u8);
            out.extend_from_slice(token);
        }
        ServerMsg::TargetAddr(addr) => {
            out.push(ServerMsgKind::TargetAddr as u8);
            match addr.ip() {
                IpAddr::V4(ip) => {
                    out.push(4);
                    out.extend_from_slice(&addr.port().to_be_bytes());
                    out.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    out.push(6);
                    out.extend_from_slice(&addr.port().to_be_bytes());
                    out.extend_from_slice(&ip.octets());
                }
            }
        }
    }
}

pub fn decode_server_msg(buf: &[u8]) -> Result<Option<(ServerMsg, usize)>, TunnelError> {
    if buf.is_empty() {
        return Ok(None);
    }
    match buf[0] {
        x if x == ServerMsgKind::SessionOffer as u8 => {
            if buf.len() < 1 + 32 {
                return Ok(None);
            }
            let mut token = [0u8; 32];
            token.copy_from_slice(&buf[1..33]);
            Ok(Some((ServerMsg::SessionOffer(token), 33)))
        }
        x if x == ServerMsgKind::TargetAddr as u8 => {
            if buf.len() < 1 + 1 + 2 {
                return Ok(None);
            }
            let family = buf[1];
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            match family {
                4 => {
                    if buf.len() < 1 + 1 + 2 + 4 {
                        return Ok(None);
                    }
                    let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                    Ok(Some((
                        ServerMsg::TargetAddr(SocketAddr::new(IpAddr::V4(ip), port)),
                        8,
                    )))
                }
                6 => {
                    if buf.len() < 1 + 1 + 2 + 16 {
                        return Ok(None);
                    }
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&buf[4..20]);
                    let ip = std::net::Ipv6Addr::from(octets);
                    Ok(Some((
                        ServerMsg::TargetAddr(SocketAddr::new(IpAddr::V6(ip), port)),
                        20,
                    )))
                }
                other => Err(TunnelError::InvalidAddrFamily(other)),
            }
        }
        other => Err(TunnelError::InvalidIntent(other)),
    }
}
